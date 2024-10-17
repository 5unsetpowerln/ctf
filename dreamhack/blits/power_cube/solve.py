#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import hashlib

exe = ptr.ELF("./chall")
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    io = connect()

    def calc_exponent():
        base = 3
        exponent = 0x456BEEFCAFEBABD + 1
        modulus = 2**64
        return pow(base, exponent, modulus)

    base = -0x2152411021524111
    exponent = calc_exponent()
    modulus = 2**64

    result = pow(base, exponent, modulus)
    hash = hashlib.sha256(ptr.p64(result))
    # print(hex(result))
    # print(hash.hexdigest())
    flag = "DH{" + hash.hexdigest() + "}"
    print(flag)

    return


if __name__ == "__main__":
    main()
