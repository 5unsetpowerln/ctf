import sys

data = sys.argv[1] 
endian = sys.argv[2]
data = data.split(' ')
if endian == "little":
    data.reverse()
    print("".join(data))
else:
    print("".join(data))
