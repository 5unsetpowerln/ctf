#!/usr/bin/env python
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def decrypt(cipher, key):
    plain = ""
    for char in cipher:
        p = (char // 311) // key
        plain += chr(p)
    return plain


def semi_decrypt(cipher, key):
    cipher_list = list(cipher)
    cipher_list.reverse()
    cipher = "".join(cipher_list)
    plain = ""
    key_length = len(key)
    for i, char in enumerate(cipher[::-1]):
        key_char = key[i % key_length]
        print(f"key_char: {ord(key_char)}")
        print(f"ec: {ord(char)}")
        decrypted_char = chr(ord(char) ^ ord(key_char))
        print(f"decrypted_char: {ord(decrypted_char)}")
        plain += decrypted_char
    return plain


a = 94
b = 29
cipher = [
    260307,
    491691,
    491691,
    2487378,
    2516301,
    0,
    1966764,
    1879995,
    1995687,
    1214766,
    0,
    2400609,
    607383,
    144615,
    1966764,
    0,
    636306,
    2487378,
    28923,
    1793226,
    694152,
    780921,
    173538,
    173538,
    491691,
    173538,
    751998,
    1475073,
    925536,
    1417227,
    751998,
    202461,
    347076,
    491691,
]

p = 97
g = 31
text_key = "trudeau"

u = generator(g, a, p)
v = generator(g, b, p)
key = generator(v, a, p)
b_key = generator(u, b, p)

shared_key = None
if key == b_key:
    shared_key = key
else:
    print("Invalid key")
    exit()

semi_cipher = decrypt(cipher, shared_key)
plain = semi_decrypt(semi_cipher, text_key)
plain_list = list(plain)
plain_list.reverse()
print("".join(plain_list))
