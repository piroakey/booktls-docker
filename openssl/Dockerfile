# OpenSSL 1.1.1a(TLS1.3 supported) container image.
#
# Get Started:
#   docker build -t tls13_openssl .
#   docker run --name tls13_openssl --rm -it tls13_openssl /bin/bash
#
# Running options:
#   - With /etc/hosts setting.
#   docker run --name tls13_openssl --rm -it --add-host remote.ubuntu:xxx.xxx.xxx.xxx --add-host remote.pi:yyy.yyy.yyy.yyy tls13_openssl /bin/bash
#
#   - With linking container.
#   docker run --name tls13_openssl --rm -it --link tls13_nginx:remote.ubuntu tls13_openssl /bin/bash
#
FROM ubuntu:20.04

LABEL maintainer="ITAKURA Hiroaki <piroakey@gmail.com>"

# OpenSSL Version (see https://www.openssl.org/source/)
ENV OPENSSL_VERSION 1.1.1h

# Noninteractive option
ENV DEBIAN_FRONTEND=noninteractive

# Add User
RUN useradd -m openssl \
 && gpasswd -a openssl sudo \
 && echo "openssl:openssl" | chpasswd

# Build as root
USER root
WORKDIR /root

# Ubuntu japanese repository
RUN sed -i.bak -e "s%http://[^ ]\+%http://ftp.jaist.ac.jp/pub/Linux/ubuntu/%g" /etc/apt/sources.list

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
        zlib-dynamic \
        enable-ec_nistp_64_gcc_128 \
 && make depend \
 && make -j ${nproc} \
 && make install_sw \
 && rm -R "/root/openssl-$OPENSSL_VERSION/"

# Add CA Cert
COPY ca.pem /home/openssl/ca.pem
RUN chown openssl:openssl /home/openssl/ca.pem

# Add tools
#COPY perf_tls12_full.sh /home/openssl/perf_tls12_full.sh
#COPY perf_tls12_resum.sh /home/openssl/perf_tls12_resum.sh
#COPY perf_tls13_full.sh /home/openssl/perf_tls13_full.sh
#COPY perf_tls13_p256.sh /home/openssl/perf_tls13_p256.sh
#COPY perf_tls13_resum.sh /home/openssl/perf_tls13_resum.sh
#COPY perf_tls13_x25519.sh /home/openssl/perf_tls13_x25519.sh
#COPY usec_perf /home/openssl/usec_perf
#RUN chown openssl:openssl /home/openssl/perf_*.sh /home/openssl/usec_perf

# Add entry script
COPY init.sh /home/openssl/init.sh
RUN chown openssl:openssl /home/openssl/init.sh

USER openssl
WORKDIR /home/openssl

# init script
RUN echo '. /home/openssl/init.sh' >> ~/.bashrc

ENTRYPOINT ["/home/openssl/init.sh", "/usr/bin/bash"]
