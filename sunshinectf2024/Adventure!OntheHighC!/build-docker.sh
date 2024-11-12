#!/bin/bash
docker rm -f container-1
docker image rm container-1
docker build -t container-1 .
# docker run --name=revkitty-test-victim-server --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
docker run -d container-1
# --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
