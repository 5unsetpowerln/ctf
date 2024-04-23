#!/usr/bin/env python

import sympy

passwd = "lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw"
length = len(passwd)


def encode(lst: list):
    for i in range(3):
        for j in range(length):
            local_28 = (j % 0xFF >> 1 & 85) + (j % 0xFF & 85)
            local_2c = (local_28 >> 2 & 51) + (51 & local_28)

            A = local_2c >> 4 & 15
            B = 15 & local_2c

            iVar1 = A + ord(lst[j]) - 97 + B

            lst[j] = chr(ord("a") + iVar1 % 0x1A)
    return "".join(lst)


def decode(lst: list):
    for i in range(3):
        for j in range(length):
            local_28 = (j % 0xFF >> 1 & 85) + (j % 0xFF & 85)
            local_2c = (local_28 >> 2 & 51) + (51 & local_28)

            A = local_2c >> 4 & 15
            B = 15 & local_2c

            enc = ord(lst[j])
            for x in range(97, 123):
                if (enc - 97) == (A + B + x - 97) % 26:
                    lst[j] = chr(x)
    return "".join(lst)


print(decode(list(passwd)))
