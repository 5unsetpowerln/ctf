#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("")
libc = ptr.ELF("")
ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "94.237.60.228:46774"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
    else:
        return ptr.Process(exe.filepath)


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
