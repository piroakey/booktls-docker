#!/bin/bash -xe

export PATH="/opt/openssl/bin:$PATH"
export LD_LIBRARY_PATH="/opt/openssl/lib"
export PKG_CONFIG_PATH="/opt/openssl/lib/pkgconfig"

openssl version

exec $*

