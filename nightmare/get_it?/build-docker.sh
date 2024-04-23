#!/bin/bash
docker rm -f getit
docker build -t getit . 
docker run --name=getit --rm -p1437:1437 -it getit
