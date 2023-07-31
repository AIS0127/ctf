FROM ubuntu:22.10

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install xinetd -y
ENV TERM=linux

RUN useradd -ms /bin/bash ctf

ADD ./share/ /home/ctf

RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf

ADD ./fit.xinetd /etc/xinetd.d/fit
CMD ["/usr/sbin/xinetd", "-dontfork"]
