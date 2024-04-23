al = "6f 63 69 70 7b 46 54 43 30 6c 5f 49 34 5f 74 35 6d 5f 6c 6c 30 6d 5f 79 5f 79 33 6e 34 63 64 62 61 65 35 32 ff f7 00 7d f7 fa ca f8 f7 f7 f4 40 22 33 f2 00 10 f7 e0 ec e9 f7 f8 00 c0 f7 f7 15 c0 f7 f7 10"
a = al.split(" ")
f = ""
for i in range(0,len(a),4):
    if i + 4 <= len(a):
        b = a[i:i+4]
        b.reverse()
        for j in b:
            f += chr(int(j,16))
print(f)        
