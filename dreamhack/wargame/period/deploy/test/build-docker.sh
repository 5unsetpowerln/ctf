#!/bin/bash
docker rm -f wargame_period
docker image rm wargame_period
docker build -t wargame_period .
# docker run --name=revkitty-test-victim-server --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
docker run -d wargame_period
# --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
