#include "pwn.h"
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <linux/prctl.h>
#include <string>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <signal.h>
#include <sys/prctl.h>
#include <vector>
#include <functional>
#include <algorithm>
#include <sys/ptrace.h>

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

    Process::Process(char *argv[])
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

        _traced = debug;

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

            if (_traced) {
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

    Process::Process(const std::string &exec)
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

            if (_traced) {
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

            char *cmd = const_cast<char *>(exec.c_str());
            char *argv[] = {cmd, NULL};
            int ret = execve(cmd, argv, environ);
            if (ret < 0) {
                perror(("cannot spawn " + exec).c_str());
                exit(EXIT_FAILURE);
            }
            exit(ret);
        }

        // Assign to private fields
        _stdout_fd = stdout_pipe[0];
        _stdin_fd  = stdin_pipe[1];
        _pid       = pid;
        _cmdline   = exec;

        // Close unused ends of pipe
        close(stdout_pipe[1]);
        close(stdin_pipe[0]);
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
        return std::string(buffer, n_bytes);
    }

    void Process::send(const std::string &data)
    {
        if (write(_stdin_fd, data.c_str(), data.length()) < 0) {
            perror(("can't write to PID: " + std::to_string(_pid)).c_str());
            exit(EXIT_FAILURE);
        }
    }
    
    void Process::sendline(const std::string &data)
    {
        send(data + '\n');
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
