#!/bin/bash -xe

trap "exit 0" SIGTERM SIGINT

export PATH="/opt/openssl/bin:$PATH"
export LD_LIBRARY_PATH="/opt/openssl/lib64/"
export PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig"

openssl version

exec $*

