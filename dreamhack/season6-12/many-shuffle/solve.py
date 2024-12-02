#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./many-shuffle")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 15484)
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


    # before = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    after = [1, 5, 12, 11, 8, 10, 6, 9, 0, 7, 2, 14, 13, 3, 15, 4]

    io.recvuntil(b"String: ")

    shuffled = io.recv(16)
    shuffled_list = []
    original = ""
    original_list = [0] * 16

    for i in shuffled:
        shuffled_list.append(i)

    for i in range(16):
        # before[after[i]] == after[i]
        original_list[after[i]] = shuffled[i]

    for i in original_list:
        original += chr(i)

    io.sendlineafter(b"String?: ", original)
    io.interactive()
    return

if __name__ == "__main__":
    main()
