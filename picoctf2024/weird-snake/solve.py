input_list = [
    4,
    54,
    41,
    0,
    112,
    32,
    25,
    49,
    33,
    3,
    0,
    0,
    57,
    32,
    108,
    23,
    48,
    4,
    9,
    70,
    7,
    110,
    36,
    8,
    108,
    7,
    49,
    10,
    4,
    86,
    43,
    108,
    122,
    14,
    2,
    71,
    62,
    115,
    88,
    78,
]

key_str = "J"
key_str += "o"
key_str += "3"
key_str += "t"


def first_listcomp(x):
    return [ord(c) for c in x]


key_list = first_listcomp(key_str)

if len(key_list) < len(input_list):
    key_list.extend(key_list)  # Duplicate key_list if it's shorter than input_list


def second_listcomp(pair):
    a, b = pair
    return a ^ b


result = list(map(second_listcomp, zip(input_list, key_list)))

result_text = "".join(map(chr, result))
print(result_text)
