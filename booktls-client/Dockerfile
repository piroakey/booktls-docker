# OpenSSL container image.
FROM ubuntu:22.04

LABEL maintainer="ITAKURA Hiroaki <piroakey@gmail.com>"

# OpenSSL Version (see https://www.openssl.org/source/)
ENV OPENSSL_VERSION 3.0.12

# Noninteractive option
ENV DEBIAN_FRONTEND=noninteractive

# Add User
RUN useradd -m openssl \
 && gpasswd -a openssl sudo \
 && echo "openssl:openssl" | chpasswd

# Build as root
USER root
WORKDIR /root

# Install deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    iproute2 \
    iputils-ping \
    net-tools \
    make \
    perl \
    sudo \
    vim \
    zlib1g-dev \
    tzdata \
    dnsutils \
    gdb \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Add sudoers
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Get sources, compile and install
RUN curl -sSLO https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz \
 && tar xvf openssl-$OPENSSL_VERSION.tar.gz \
 && rm -v openssl-$OPENSSL_VERSION.tar.gz \
 && cd "/root/openssl-$OPENSSL_VERSION/" \
 && ./config --prefix=/opt/openssl \
        shared \
        enable-ec_nistp_64_gcc_128 \
 && make depend \
 && make -j ${nproc} \
 && make install_sw \
 && rm -R "/root/openssl-$OPENSSL_VERSION/"

# Add CA Cert
COPY ca.pem /home/openssl/ca.pem
RUN chown openssl:openssl /home/openssl/ca.pem

# Add entry script
COPY init.sh /home/openssl/init.sh
RUN chown openssl:openssl /home/openssl/init.sh

# Add .vimrc
COPY .vimrc /home/openssl/.vimrc
RUN chown openssl:openssl /home/openssl/.vimrc

# share
RUN mkdir -p /share
RUN chown -R openssl:openssl /share

USER openssl
WORKDIR /home/openssl

# init script
RUN echo '. /home/openssl/init.sh' >> ~/.bashrc

ENTRYPOINT ["/home/openssl/init.sh", "/usr/bin/bash"]
