#!/bin/bash
docker rm -f rtld
docker image rm rtld
docker build -t rtld .
docker run -d rtld
