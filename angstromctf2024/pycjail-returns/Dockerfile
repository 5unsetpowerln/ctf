FROM pwn.red/jail

EXPOSE 5000
COPY --from=python:3.12-slim-bookworm / /srv
COPY chall.py /srv/app/run
RUN chmod +x /srv/app/run
COPY flag.txt /srv/app/flag.txt
