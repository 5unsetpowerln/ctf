#!/bin/bash
docker image rm angstromctf2024-heapify
docker rm -f angstromctf2024-heapify
docker build -t angstromctf2024-heapify . 
docker run --name=angstromctf2024-heapify --privileged --rm -p1337:1337 -it angstromctf2024-heapify 
