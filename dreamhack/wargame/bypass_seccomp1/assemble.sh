#!/bin/bash

nasm -f elf64 shellcode.asm
objcopy --dump-section .text=shellcode.bin shellcode.o
