#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./vuln_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def main():
    io = connect()

    io.sh()


if __name__ == "__main__":
    main()
