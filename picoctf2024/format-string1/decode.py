import sys

raw = sys.argv[1]
data = raw.split(".")
output = b""
for i in data:
    output += int(i,16).to_bytes(8, "little")
print(output)
