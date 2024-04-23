#!/usr/bin/env python

import subprocess
import ptrlib as ptr
import pwn
import random


def rand():
    output = subprocess.Popen(
        "./rand", stdout=subprocess.PIPE, shell=True
    ).communicate()[0]

    if isinstance(output, bytes):
        return str(int(output.decode().strip(), 16)).encode()
    else:
        ptr.logger.error("failed to generate rand")
        exit()


io = pwn.remote("spaceheroes-atm.chals.io", 443, ssl=True)
# io = pwn.process("./atm.bin")

io.sendline(b"w")
io.sendline(rand())

io.interactive()
