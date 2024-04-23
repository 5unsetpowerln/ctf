#!/usr/bin/env python

import pwn

io = pwn.remote(
    "spaceheroes-a-riscv-maneuver.chals.io",
    443,
    ssl=True,
    # sni="spaceheroes-a-riscv-maneuver.chals.io",
)

io.interactive()
