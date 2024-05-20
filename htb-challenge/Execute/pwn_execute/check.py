#!/usr/bin/env python
import sys, pwn

blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"
shellcode = sys.argv[1].split(" ")
for i in shellcode:
    b = int(i, 16)
    for j in blacklist:
        print(hex(b), hex(j))
        if j == b:
            print("(;_;)")
            sys.exit(1)
