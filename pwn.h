#pragma once
#include <cstdlib>
#include <sched.h>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

std::string operator*(std::string str, int n);

namespace pwn {
    // Context flag to determine if debug mode should be enabled
    extern bool debug;

    /*
     * Convert a 32bit little endian unsigned integer into a 4 byte string
     * @param i (uint32_t) integer to pack
     */
    std::string p32(uint32_t i);
    /*
     * Convert a 64bit little endian unsigned integer into a 8 byte string
     * @param i (uint64_t) integer to pack
     */
    std::string p64(uint64_t i);
    /*
     * Generate a deBruijn sequence of length n
     * @param n (int) length of sequence
     */
    std::string cyclic(int n);
    /*
     * Generate the full deBruijn sequence of a k-sized alphabet of order n
     * @param k (int) number of alphabets in the sequence
     * @param n (int) order of de Bruijn sequence
     */
    std::string deBruijn(int k, int n);

    /*
     * Tube class describes an interface that does IO with
     * an external interface like stdio/sockets
     */
    class Tube
    {
    public:
        virtual void send(const std::string &data) = 0;
        virtual std::string recv(const size_t size) = 0;
        virtual bool wait_term() = 0;
        void sendline(const std::string &data);
        std::string recvall();
    };

    class Process: public Tube
    {
    public:
        Process(const std::string &exec);
        Process(char *argv[]);
        ~Process();

        void send(const std::string &data) override;
        std::string recv(const size_t size) override;
        pid_t pid() { return _pid; }
        std::string cmdline() { return _cmdline; }
        bool traced() { return _traced; }
        bool wait_term() override;

    private:
        void start_process(char *argv[], const bool trace = false);
        int _stdout_fd, _stdin_fd;
        pid_t _pid;
        std::string _cmdline;
        bool _traced;
    };

    class Remote: public Tube
    {
    public:
        Remote(const std::string &host, const int port, int socktype = SOCK_STREAM);
        ~Remote();

        void send(const std::string &data) override;
        std::string recv(const size_t size) override;
        bool wait_term() override;
    private:
        std::string _host;
        int _port, _sockfd, _connfd;
        struct addrinfo *_addrinfo;
    };

    namespace gdb {
        void attach(Process &proc);
    }
}
