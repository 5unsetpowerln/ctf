#!/usr/bin/env python

import ptrlib as ptr

exe = ptr.ELF("./test")
io = ptr.Process(exe.filepath)

size = 0x20
payload = b""
# payload += b"\xff

io.send("b" * 0x20)
print(io.recvonce(0x20))

io.sh()
