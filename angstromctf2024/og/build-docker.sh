#!/bin/bash
docker rm -f angstromctf2024-og
docker build -t angstromctf2024-og .
docker run --name=angstromctf2024-og --privileged --rm -p1337:1337 -it angstromctf2024-og
