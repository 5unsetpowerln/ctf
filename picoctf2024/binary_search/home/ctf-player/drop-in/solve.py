#!/usr/bin/env python
import pwn

io = pwn.ssh(host='tlas.picoctf.net', user='ctf-player', port=56711, password='6dd28e9b')
io = io.process()

