#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./main")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("/lib/x86_64-linux-gnu/libc.so.6")
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

    io.interactive()
    return

if __name__ == "__main__":
    main()
