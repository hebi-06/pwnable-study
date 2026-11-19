FROM ubuntu:24.04@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02

ENV user chall
ENV chall_port 31337

RUN apt-get update
RUN apt-get install -y socat adduser

RUN adduser $user -u 1337

ADD ./deploy/fastbin_dup /home/$user/fastbin_dup

RUN chown root:$user /home/$user/fastbin_dup
RUN chmod 755 /home/$user/fastbin_dup

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD socat TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/fastbin_dup