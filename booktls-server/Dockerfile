# Nginx build with OpenSSL container image.
FROM ubuntu:22.04

LABEL maintainer="ITAKURA Hiroaki <piroakey@gmail.com>"

# OpenSSL Version (see https://www.openssl.org/source/)
ENV OPENSSL_VERSION 3.0.7

# Nginx Version (see https://nginx.org/en/download.html)
ENV NGINX_VERSION 1.22.1

# Noninteractive option
ENV DEBIAN_FRONTEND=noninteractive

# Add User
RUN useradd -m openssl \
 && gpasswd -a openssl sudo \
 && echo "openssl:openssl" | chpasswd

# Build as root
USER root
WORKDIR /root

# www-data user
RUN usermod www-data --home /etc/nginx --shell /sbin/nologin

# Install deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    libpcre3 \
    libpcre3-dev \
    make \
    perl \
    sudo \
    vim \
    zlib1g-dev \
    libxslt-dev \
    libgd-dev \
    tzdata \
    dnsutils \
    gdb \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

 # Add sudoers
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

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

RUN curl -sSLO https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz \
 && curl -sSLO https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz \
 && tar xzvf openssl-$OPENSSL_VERSION.tar.gz \
 && rm -v openssl-$OPENSSL_VERSION.tar.gz \
 && tar xzvf nginx-$NGINX_VERSION.tar.gz \
 && rm -v nginx-$NGINX_VERSION.tar.gz \
 && cd "/root/nginx-$NGINX_VERSION/" \
 && ./configure --with-cc-opt='-O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' \
        --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC' \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --http-log-path=/var/log/nginx/access.log \
        --error-log-path=/var/log/nginx/error.log \
        --lock-path=/var/lock/nginx.lock \
        --pid-path=/run/nginx.pid \
        --modules-path=/usr/lib/nginx/modules \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --with-compat \
        --with-pcre-jit \
        --with-http_ssl_module \
        --with-http_stub_status_module \
        --with-http_realip_module \
        --with-http_auth_request_module \
        --with-http_v2_module \
        --with-http_dav_module \
        --with-http_slice_module \
        --with-threads \
        --with-http_addition_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_image_filter_module=dynamic \
        --with-http_sub_module \
        --with-http_xslt_module=dynamic \
        --with-stream=dynamic \
        --with-stream_ssl_module \
        --with-mail=dynamic \
        --with-mail_ssl_module \
        --with-openssl="$HOME/openssl-$OPENSSL_VERSION" \
        --with-openssl-opt="enable-ec_nistp_64_gcc_128" \
 && make -j ${nproc} \
 && make install \
 && rm -R "/root/nginx-$NGINX_VERSION" \
 && rm -R "/root/openssl-$OPENSSL_VERSION/"

# Add entry script
COPY init.sh /home/openssl/init.sh
RUN chown openssl:openssl /home/openssl/init.sh

# share
RUN mkdir -p /share
RUN chown -R openssl:openssl /share

# Copy cert and /etc/nginx/nginx.conf etc.
COPY conf/nginx.conf /etc/nginx/nginx.conf

COPY certs/server.crt /etc/nginx/certs/server.crt
COPY certs/server.key /etc/nginx/certs/server.key

# Make sure the permissions are set.
RUN chown -R www-data:www-data /etc/nginx \
 && chown -R www-data:www-data /var/log/nginx \
 && mkdir -p /var/cache/nginx/ \
 && chown -R www-data:www-data /var/cache/nginx/ \
 && touch /var/run/nginx.pid \
 && chown -R www-data:www-data /var/run/nginx.pid

# build options report
RUN nginx -V

USER openssl
WORKDIR /home/openssl

# init script
RUN echo '. /home/openssl/init.sh' >> ~/.bashrc

# Launch
USER www-data
WORKDIR /etc/nginx

# 10080:http 10443:https(tls1.3, tls1.2)
# 10444:https(minimal curves)
# 443: https(original prog)
EXPOSE 443 10080 10443 10444

CMD ["nginx", "-g", "daemon off;"]
