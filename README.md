<h1 align="center">Mini C++ Pwnlib</h1>
<p align="center">
    <img alt="GitHub top language" src="https://img.shields.io/github/languages/top/nankeen/pwnlib-cpp?style=for-the-badge">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/nankeen/pwnlib-cpp?style=for-the-badge">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/nankeen/pwnlib-cpp?style=for-the-badge">
</p>

This is a small C++ library that implements some features from pwntools.
It was mainly a hack I wrote to be used in an environment without python3 and pwntools.

## Usage

exploit.cc:

```cpp
#include "pwn.h"
#include <iostream>

using namespace pwn;

int main(int argc, char *argv[])
{
    // Debug mode
    // pwn::debug = true;
    auto win = 0x8048556;

    // We're all about precision exploits here
    auto payload = p32(win) * 50;

    auto io = Process("./vuln");
    // gdb::attach(io); // Must be used with tmux
    io.sendline(payload);
    std::cout << io.recvall() << std::endl;
    return 0;
}
```

Compile it with:

```bash
g++ exploit.cc pwn.cc -o exploit
```

`pwn.cc` and `pwn.h` should be in the same directory as `exploit.cc`.
