xor rax, rax
xor rdi, rdi
xor rsi, rsi
mov rdi, 0x0
mov edx, 0x3c
lea rax, [rbp-0x50]
mov rsi, rax
xor rax, rax
mov rax, 0x0
syscall
lea rax, [rbp-0x50]
call rax
