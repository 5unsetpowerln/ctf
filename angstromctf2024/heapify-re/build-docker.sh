#!/bin/bash
docker rm -f angstromctf2024-heap
docker build -t angstromctf2024-heap .
docker run --name=angstromctf2024-heap --privileged --rm -p1337:1337 -it angstromctf2024-heap
