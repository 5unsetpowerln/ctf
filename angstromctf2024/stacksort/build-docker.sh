#!/bin/bash
docker rm -f angstromctf2024-stackport
docker build -t angstromctf2024-stackport .
docker run --name=angstromctf2024-stackport --privileged --rm -p1337:1337 -it angstromctf2024-stackport
