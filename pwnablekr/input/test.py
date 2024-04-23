from pwn import *

con = process("./test")
con.send(b"\x00\x0a\x00\xff")
res = con.recv_raw(1024)
print(res)
con.send(b"B")
res = con.recvall(timeout=1)
print(res)
