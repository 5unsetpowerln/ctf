for i in range(0x1000):
    num = (0xFFFF * i) & 0xFFFF
    print(i, hex(num))
    if num == 0x4010 or num == 0x4011:
        break
