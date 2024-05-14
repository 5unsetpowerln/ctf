#!/bin/bash
docker rm -f web_spook_tastic
docker build -t web_spook_tastic . 
docker run --name=web_spook_tastic --rm -p1337:1337 -it web_spook_tastic
