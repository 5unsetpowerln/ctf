flag = "/home/shell_basic/flag_name_is_loooooong"
# flag = "flag_name_is_loooooong"

flag_li = list(flag)

for i in range(len(flag_li) + 8 // 8):
    part_li = flag_li[i * 8 : (i + 1) * 8]
    part_li.reverse()
    hex_value = "0x"
    for j in part_li:
        hex_value += j.encode().hex()
    print(hex_value)
