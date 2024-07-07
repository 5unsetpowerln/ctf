#!/usr/bin/env python
import ptrlib as ptr
import sys

exe = ptr.ELF("./sheep_patched")
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        addr = "94.237.60.228:46774"
        addr = addr.split(":")
        host = addr[0]
        port = int(addr[1])
        return ptr.Socket(host, port)
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

    def buy(type_: int) -> int:
        io.sendlineafter("heep type> ", str(type_))
        return int(io.recvlineafter("sheep bought, sitting at index: ").strip(b"\n"))

    # 持っているwoolがupgrade_type * 10よりも大きくないとupgradeできない
    def upgrade(index: int, upgrade_type: int):
        io.sendlineafter("index> ", str(index))
        io.sendlineafter("upgrade type> ", str(upgrade_type))
        return

    def sell(index: int):
        io.sendlineafter("index> ", str(index))
        return

    def view(index: int) -> bytes:
        io.sendlineafter("index> ", str(index))
        return io.recvuntil("Time:").strip(b"Time:")

    io.sh()


if __name__ == "__main__":
    main()
