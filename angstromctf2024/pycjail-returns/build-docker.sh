#!/bin/bash
docker image rm angstromctf2024-pycjail-returns
docker rm -f angstromctf2024-pycjail-returns
docker build -t angstromctf2024-pycjail-returns . 
docker run --name=angstromctf2024-pycjail-returns --privileged --rm -p5000:5000 -it angstromctf2024-pycjail-returns
