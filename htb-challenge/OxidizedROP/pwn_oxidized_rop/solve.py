#!/usr/bin/env python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        print("failed to unwrap")
        exit(1)
    else:
        return x


elf = ptr.ELF("./oxidized-rop")

for i in range(300):
    io = ptr.Process(elf.filepath)

    io.sendline(b"1")
    io.sendline("あ" * (i + 1))

    io.recvuntil(b"Statement (max 200 characters):")
    print(i, io.recvline())
