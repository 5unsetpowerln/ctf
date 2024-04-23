#!/usr/bin/env python

with open("./file", "rb") as f:
    data = list(f.read())

output = []

print(len(data))
for i in range(0, len(data) // 4, 1):
    each = data[i * 4 : i * 4 + 4]
    each.reverse()
    for j in each:
        output.append(j)


with open("./file.out", "wb") as f:
    f.write(bytes(output))
