#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import ctypes
import time

exe = ptr.ELF("./cat_jump")
# libc = ptr.ELF("")
# ld = ptr.ELF("")
cdll = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 12311)
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
    cdll.srand(cdll.time(0))

    RAND_MAX = 2147483647
    CAT_JUMP_GOAL = 37
    CATNIP_PROBABILITY = 0.1
    CATNIP_INVINCIBLE_TIMES = 3
    catnip = 0
    jump_cnt = 0

    for i in range(36):
        obstacle = cdll.rand() % 2
        try:
            if obstacle != 0:
                io.sendline(b"h")
                print(i, io.recvuntil(b"left jump='h', right jump='j':"))
            if obstacle != 1:
                io.sendline(b"j")
                print(i, io.recvuntil(b"left jump='h', right jump='j':"))
        except EOFError:
            io.interactive()
            break
        cdll.rand()

    io.interactive()
    return


if __name__ == "__main__":
    main()
