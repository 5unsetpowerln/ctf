ebp = 0xffffd438
input_addr = ebp - 0x6c
return_addr_addr = 0xffffd43c
win_addr = 0x0804929a
arg1_addr = ebp + 0x8
arg2_addr = ebp + 0xc

print(input_addr)
print(input_addr - return_addr_addr)
