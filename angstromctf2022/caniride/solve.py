#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("")
libc = ptr.ELF("")
ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    io.sh()


if __name__ == "__main__":
    main()
