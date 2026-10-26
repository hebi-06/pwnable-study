FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt-get update && apt-get install -y socat

RUN adduser pwn

WORKDIR /home/pwn

COPY ./deploy/flag ./flag
COPY ./deploy/main ./main

RUN chmod 644 ./flag 
RUN chmod 755 ./main

USER pwn

EXPOSE 5000
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:./main,stderr