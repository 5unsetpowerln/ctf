#!/usr/bin/env python
from paramiko import SSHClient, AutoAddPolicy


def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"

print(shellquote("/bin/bash'"))
