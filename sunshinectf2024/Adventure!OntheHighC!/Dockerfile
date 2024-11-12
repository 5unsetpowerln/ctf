FROM tjoconnor/bin-hosting

RUN apt-get update -qq -y && apt-get -qq -y install gdb git python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential tmux
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

RUN pip3 install ptrlib
RUN pip3 install pwntools

COPY solve.py /solve.py
COPY ship.bin /chal
COPY flag.txt /flag.txt
