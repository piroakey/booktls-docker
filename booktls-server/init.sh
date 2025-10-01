#!/bin/bash -xe

trap "exit 0" SIGTERM SIGINT

export PATH="/opt/openssl/bin:$PATH"

if [ -d /opt/openssl/lib ]; then
  export LD_LIBRARY_PATH="/opt/openssl/lib:$LD_LIBRARY_PATH"
  export PKG_CONFIG_PATH="/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
fi
if [ -d /opt/openssl/lib64 ]; then
  export LD_LIBRARY_PATH="/opt/openssl/lib64:$LD_LIBRARY_PATH"
  export PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig:$PKG_CONFIG_PATH"
fi

openssl version

exec $*
