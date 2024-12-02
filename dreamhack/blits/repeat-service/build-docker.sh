#!/bin/bash
docker rm -f repeat-service
docker image rm repeat-service
docker build -t repeat-service .
# docker run --name=revkitty-test-victim-server --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
docker run -d repeat-service
# --rm -i revkitty-test-victim-server '/revr-server --ip 172.17.0.1 --port 4444' 
