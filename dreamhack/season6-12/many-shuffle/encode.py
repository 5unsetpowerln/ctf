import random
import struct

# DAHYQZHRXQXSUFTX
# original_string = b"XDXFXAHQQRZYHUST"
# original_string = b"0123456789abcdef"
shuffled_string = [0,1,2,3,4,5,6,7,8,9,10, 11, 12, 13, 14, 15]
original_string = [0,1,2,3,4,5,6,7,8,9,10, 11, 12, 13, 14, 15]
# for i in original_string:
    # shuffled_string.append(i)

# 0x555555554000
#
data_4020 = [
	0x0b, 0x08, 0x03, 0x04, 0x01, 0x00, 0x0e, 0x0d, 0x0f, 0x09, 0x0c, 0x06, 0x02, 0x05, 0x07, 0x0a,
	0x0f, 0x04, 0x08, 0x0b, 0x06, 0x07, 0x0d, 0x02, 0x0c, 0x03, 0x05, 0x0e, 0x0a, 0x00, 0x01, 0x09,
	0x04, 0x0c, 0x0e, 0x05, 0x0d, 0x06, 0x09, 0x0a, 0x01, 0x00, 0x0b, 0x0f, 0x02, 0x07, 0x03, 0x08,
	0x0a, 0x08, 0x0f, 0x03, 0x04, 0x06, 0x00, 0x0b, 0x01, 0x0d, 0x09, 0x07, 0x05, 0x02, 0x0c, 0x0e,
	0x0b, 0x06, 0x09, 0x0f, 0x02, 0x01, 0x0a, 0x0e, 0x03, 0x0c, 0x0d, 0x00, 0x05, 0x04, 0x08, 0x07,
	0x09, 0x04, 0x0b, 0x05, 0x06, 0x0f, 0x08, 0x00, 0x03, 0x01, 0x0a, 0x0d, 0x02, 0x0e, 0x0c, 0x07,
	0x0a, 0x0e, 0x09, 0x07, 0x08, 0x0d, 0x03, 0x0b, 0x0c, 0x0f, 0x02, 0x00, 0x04, 0x05, 0x06, 0x01,
	0x05, 0x04, 0x0d, 0x01, 0x00, 0x02, 0x09, 0x0b, 0x0c, 0x07, 0x08, 0x0a, 0x06, 0x0e, 0x0f, 0x03,
	0x04, 0x08, 0x05, 0x02, 0x0a, 0x0f, 0x0b, 0x07, 0x00, 0x01, 0x0c, 0x03, 0x0e, 0x06, 0x09, 0x0d,
	0x0d, 0x0e, 0x0f, 0x0b, 0x00, 0x02, 0x0a, 0x04, 0x07, 0x06, 0x09, 0x01, 0x05, 0x03, 0x08, 0x0c,
	0x0e, 0x02, 0x03, 0x05, 0x0a, 0x01, 0x07, 0x00, 0x09, 0x0d, 0x0c, 0x0b, 0x04, 0x06, 0x0f, 0x08,
	0x03, 0x0b, 0x0e, 0x0a, 0x06, 0x04, 0x07, 0x01, 0x02, 0x0d, 0x0f, 0x00, 0x0c, 0x09, 0x05, 0x08,
	0x0d, 0x0f, 0x01, 0x02, 0x0c, 0x0a, 0x03, 0x07, 0x09, 0x06, 0x08, 0x05, 0x00, 0x04, 0x0b, 0x0e,
	0x00, 0x0e, 0x04, 0x0d, 0x06, 0x01, 0x0a, 0x05, 0x03, 0x0c, 0x07, 0x0b, 0x0f, 0x02, 0x08, 0x09,
	0x0b, 0x02, 0x08, 0x07, 0x05, 0x03, 0x09, 0x0d, 0x04, 0x0f, 0x00, 0x01, 0x06, 0x0c, 0x0e, 0x0a,
	0x0b, 0x01, 0x08, 0x00, 0x0c, 0x0d, 0x04, 0x0e, 0x0a, 0x06, 0x0f, 0x07, 0x09, 0x05, 0x03, 0x02
];

var68 = [0] * 16
for i in range(16):
    for j in range(16):
        index = data_4020[i * 16 + j]
        if i & 1 == 0:
            var68[index] = shuffled_string[j]
            if chr(shuffled_string[j]) == "D":
                print(f"var68[{index}] = shuffled_string[{j}] = {chr(shuffled_string[j])}")
        else:
            shuffled_string[index] = var68[j]
            if chr(var68[j]) == "D":
                print(f"shuffled_string[{index}] = var68[{j}] = {chr(var68[j])}")


before = original_string
after = shuffled_string

# table = [0] * 16

shuffled = b"DAHYQZHRXQXSUFTX"
shuffled_list = []
original = ""
original_list = [0] * 16
for i in shuffled:
    shuffled_list.append(i)

for i in range(16):
    # before[after[i]] == after[i]
    original_list[after[i]] = shuffled[i]

for i in original_list:
    original += chr(i)

print(original)
