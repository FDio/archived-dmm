FROM docker.io/centos:latest

RUN yum install -y git vim sudo ethtool

RUN yum install -y kernel-devel-`uname -r`
RUN yum install -y kernel-`uname -r`

RUN git config --global http.sslVerify false
RUN git config --global user.email "you@example.com"
RUN git config --global user.name "Your Name"

RUN git clone https://gerrit.fd.io/r/dmm

RUN mkdir -p /var/run/ip_module/
RUN mkdir -p /var/log/nStack/ip_module/

RUN cd /dmm/scripts/ && bash -x build.sh && cd /dmm/ && git clean -dfx ./ && git checkout ./
