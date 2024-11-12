FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

ENV user dbg

RUN apt-get update
RUN apt-get install -y socat

RUN adduser $user

ADD ./flag /home/$user/flag
ADD ./deploy/main /home/$user/main

RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/main

RUN chmod 440 /home/$user/flag
RUN chmod 755 /home/$user/main

WORKDIR /home/$user
USER $user

EXPOSE 1337
CMD socat -T 90 TCP-LISTEN:1337,reuseaddr,fork EXEC:./main