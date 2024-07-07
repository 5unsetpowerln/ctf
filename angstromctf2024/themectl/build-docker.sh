#!/bin/bash
docker rm -f angstromctf2024-themectl
docker build -t angstromctf2024-themectl .
docker run --name=angstromctf2024-themectl --privileged --rm -p1337:1337 -it angstromctf2024-themectl
