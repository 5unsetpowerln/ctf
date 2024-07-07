#!/bin/bash
docker rm -f angstromctf2023-slack
docker build -t angstromctf2023-slack . 
docker run --name=angstromctf2023-slack --privileged --rm -p1337:1337 -it angstromctf2023-slack /bin/sh
