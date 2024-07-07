import ptrlib as ptr

elf = ptr.ELF("./hft_patched")
libc = ptr.ELF("./libc.so.6")

io = ptr.Process(elf.filepath)

input(">>>")
