#!/bin/bash
docker rm -f cat_jump
docker image rm cat_jump
docker build -t cat_jump .
# docker run --name=revkitty-test-victim-server --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
docker run -d cat_jump
# --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
