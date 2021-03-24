#pragma once
#include <cstddef>
#include <sched.h>
#include <string>

std::string operator*(std::string str, int n);

namespace pwn {
    std::string p32(uint32_t i);
    std::string p64(uint64_t i);
    std::string cyclic(int n);
    std::string deBruijn(int k, int n);

    extern bool debug;

    class Tube
    {
    public:
        virtual void send(const std::string &data) = 0;
        virtual std::string recv(const size_t size) = 0;
    };

    class Process: Tube
    {
    public:
        Process(const std::string &exec);
        Process(char *argv[]);
        ~Process();

        void send(const std::string &data);
        void sendline(const std::string &data);
        std::string recv(const size_t size);
        pid_t pid() { return _pid; }
        std::string cmdline() { return _cmdline; }
        bool traced() { return _traced; }

    private:
        int _stdout_fd, _stdin_fd;
        pid_t _pid;
        std::string _cmdline;
        bool _traced;
    };

    namespace gdb {
        void attach(Process &proc);
    }
}
