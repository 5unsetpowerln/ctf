#!/usr/bin/env python3

import pwn

libc = pwn.ELF("./libc-2.23.so")

io = pwn.process("./svc", env={"LD_PRELOAD": "/home/ryohz/pentest/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"})
# io = pwn.process("./svc", env={"LD_PRELOAD" : "/home/ryohz/pentest/nightmare/csaw17svc/libc-2"})
res = io.recvall(timeout=1)
print(res.decode())
