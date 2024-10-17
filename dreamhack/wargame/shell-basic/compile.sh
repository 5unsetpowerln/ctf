#!/bin/bash

nasm -f elf64 solve.asm
objcopy --dump-section .text=solve.bin solve.o
