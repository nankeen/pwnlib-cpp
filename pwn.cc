#include "pwn.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <iostream>
#include <sys/socket.h>
#include <vector>
#include <functional>
#include <algorithm>

#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>

std::string operator*(std::string str, int n)
{
    std::string tmp = "";
    for (size_t i = 0; i < n; i++) {
        tmp += str;
    }
    return tmp;
}

namespace pwn {
    bool debug = false;

    std::string p64(uint64_t i)
    {
        return std::string((char *)&i, 8);
    }

    std::string p32(uint32_t i)
    {
        return std::string((char *)&i, 4);
    }

    std::string cyclic(int n)
    {
        std::string out;
        auto db = deBruijn(26, 4);
        std::copy_n(db.begin(), n, std::back_inserter(out));
        return out;
    }

    // Generate a deBruijn sequence of size k alphabet and order n
    std::string deBruijn(int k, int n)
    {
        std::vector<char> a(k * n, 0);
        std::vector<char> seq;
     
        std::function<void(int, int)> db;
        db = [&](int t, int p) {
            if (t > n) {
                if (n % p == 0) {
                    for (int i = 1; i < p + 1; i++) {
                        seq.push_back(a[i]);
                    }
                }
            } else {
                a[t] = a[t - p];
                db(t + 1, p);
                auto j = a[t - p] + 1;
                while (j < k) {
                    a[t] = j & 0xFF;
                    db(t + 1, t);
                    j++;
                }
            }
        };
     
        db(1, 1);
        std::string buf;
        for (auto i : seq) {
            buf.push_back('a' + i);
        }
        return buf + buf.substr(0, n - 1);
    }
    
    void Tube::sendline(const std::string &data)
    {
        send(data + '\n');
    }

    std::string Tube::recvall()
    {
        int status;
        std::string result, tmp;
        wait_term();
        do {
            auto tmp = recv(4096);
            result += tmp ;
        } while(tmp != "");
        return result;
    }

    Process::Process(char *argv[])
    {
        start_process(argv);
    }

    Process::Process(const std::string &exec)
    {
        char *cmd = const_cast<char *>(exec.c_str());
        char *argv[] = {cmd, NULL};
        start_process(argv, debug);
    }

    Process::~Process()
    {
        close(_stdout_fd);
        close(_stdin_fd);
        kill(_pid, SIGKILL);
    }

    std::string Process::recv(const size_t size)
    {
        char *buffer = new char[size];
        ssize_t n_bytes = read(_stdout_fd, buffer, size);
        if (n_bytes == -1) {
            perror(("can't read from PID: " + std::to_string(_pid)).c_str());
            exit(EXIT_FAILURE);
        }
        auto result = std::string(buffer, n_bytes);
        delete[] buffer;
        return result;
    }

    void Process::send(const std::string &data)
    {
        if (write(_stdin_fd, data.c_str(), data.length()) < 0) {
            perror(("can't write to PID: " + std::to_string(_pid)).c_str());
            exit(EXIT_FAILURE);
        }
    }

    void Process::start_process(char *argv[], const bool debug)
    {
        // Setup pipes we will use for the child process
        int stdout_pipe[2], stdin_pipe[2];
        if (pipe(stdout_pipe) != 0) {
            perror("failed stdout pipe setup");
            exit(EXIT_FAILURE);
        }
        if (pipe(stdin_pipe) != 0) {
            perror("failed stdin pipe setup");
            exit(EXIT_FAILURE);
        }

        // Fork to spawn child process
        pid_t pid = fork();
        if (pid == -1) {
            perror("failed fork");
            exit(EXIT_FAILURE);
        }

        if (pid == 0) {
            // Child should bind pipes and execute command
            // Duplicate fd
            if (dup2(stdout_pipe[1], STDOUT_FILENO) == -1) {
                perror("failed stdout duplication");
                exit(EXIT_FAILURE);
            }
            if (dup2(stdin_pipe[0], STDIN_FILENO) == -1) {
                perror("failed stdin duplication");
                exit(EXIT_FAILURE);
            }

            if (debug) {
                prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
                // Wait for GDB attach signal this is a hack...
                char tmp;
                while(read(stdin_pipe[0], &tmp, 1) > 0 && tmp != '\x69') {}
            }

            // Close all the useless fds
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
            close(stdin_pipe[0]);
            close(stdin_pipe[1]);

            int ret = execve(argv[0], argv, environ);
            if (ret < 0) {
                perror(("cannot spawn " + std::string(argv[0])).c_str());
                exit(EXIT_FAILURE);
            }
            exit(ret);
        }

        // Assign to private fields
        _stdout_fd = stdout_pipe[0];
        _stdin_fd  = stdin_pipe[1];
        _pid       = pid;
        _cmdline   = argv[0];

        // Close unused ends of pipe
        close(stdout_pipe[1]);
        close(stdin_pipe[0]);
    }

    bool Process::wait_term()
    {
        int status;
        pid_t w = waitpid(_pid, &status, 0);
        if (w == -1) {
            perror("wait pid failure");
            return false;
        }
        return true;
    }

    Remote::Remote(const std::string &host, const int port, int socktype)
    {
        _host = host;
        _port = port;
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
        hints.ai_socktype = socktype;
        hints.ai_flags    = 0;
        hints.ai_protocol = 0;          /* Any protocol */

        auto port_string = std::to_string(port);

        if (getaddrinfo(host.c_str(), port_string.c_str(), &hints, &_addrinfo) != 0) {
            perror(("Could not get address info for: " + host + ":" + port_string).c_str());
            exit(EXIT_FAILURE);
        }

        if((_sockfd = socket(_addrinfo->ai_family, _addrinfo->ai_socktype, _addrinfo->ai_protocol)) < 0) {
            perror("socket creation failed");
            exit(EXIT_FAILURE);
        }
        if((_connfd = connect(_sockfd, _addrinfo->ai_addr, _addrinfo->ai_addrlen)) < 0) {
            perror("connection failed");
            exit(EXIT_FAILURE);
        }
    }

    Remote::~Remote()
    {
        freeaddrinfo(_addrinfo);
        close(_sockfd);
        close(_connfd);
    }

    void Remote::send(const std::string &data)
    {
        if (::send(_sockfd, data.c_str(), data.length(), 0) < 0) {
            perror("can't send with connection");
            exit(EXIT_FAILURE);
        }
    }

    std::string Remote::recv(const size_t size)
    {
        char *buffer = new char[size];
        ssize_t n_bytes = ::recv(_sockfd, buffer, size, 0);
        if (n_bytes == -1) {
            perror("can't read from connection");
            exit(EXIT_FAILURE);
        }
        auto result = std::string(buffer, n_bytes);
        delete[] buffer;
        return result;
    }

    bool Remote::wait_term()
    {
        return true;
    }

    namespace gdb {
        void attach(Process &proc)
        {
            pid_t fpid = fork();
            if (fpid == 0) {
                // Child
                // Convert the GDB command into a C string
                char *cmd;
                if (asprintf(&cmd, "tmux split-window gdb -q %s %d", proc.cmdline().c_str(), proc.pid()) < 0 || cmd == NULL) {
                    std::cerr << "Can't convert PID to C string" << std::endl;
                    exit(EXIT_FAILURE);
                }

                // Spawn a new tmux window with gdb
                int ret = system(cmd);
                if (ret != 0) {
                    perror(("cannot attach to " + std::string(cmd)).c_str());
                    exit(EXIT_FAILURE);
                }
                // Detty hack
                if (proc.traced()) {
                    sleep(1);
                    proc.send("\x69");
                }
                free(cmd);
                exit(ret);
            }

        }
    }
}
