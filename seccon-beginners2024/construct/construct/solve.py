#!/usr/bin/env python

lines = ""

with open("./flag.txt", "r") as f:
    lines = f.read()

line_list = lines.splitlines()

flag = ""

for i in range(len(line_list)):
    line = line_list[i]
    flag += "".join(list(line)[i*2 : i*2 + 2])

print(flag)
