#!/usr/bin/python
import sys

print(sys.argv)

if len(sys.argv)==2:
    print("Knock, Knock, {0}".format(sys.argv[1]))
else:
    sys.stderr.write("Usage: {0} <name>".format(sys.argv[0]));

