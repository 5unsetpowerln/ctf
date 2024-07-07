#!/bin/bash
docker rm -f angstromctf2023-widget
docker build -t angstromctf2023-widget . 
docker run --name=angstromctf2023-widget --privileged --rm -p1337:1337 -it angstromctf2023-widget /bin/sh
