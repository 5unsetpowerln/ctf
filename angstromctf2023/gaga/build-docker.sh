#!/bin/bash
docker rm -f angstromctf2023-gaga
docker build -t angstromctf2023-gaga . 
# docker run --name=angstromctf2023-gaga --rm -p1337:1337 -it angstromctf2023-gaga
