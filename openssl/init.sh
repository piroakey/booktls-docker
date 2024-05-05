#!/bin/bash -xe

trap "exit 0" SIGTERM SIGINT

export PATH="/opt/openssl/bin:$PATH"

if [ -e "/opt/openssl/lib" ]; then
	export LD_LIBRARY_PATH="/opt/openssl/lib"
	export PKG_CONFIG_PATH="/opt/openssl/lib/pkgconfig"
elif [ -e "/opt/openssl/lib64" ]; then # Path for 64 bit host 
	export LD_LIBRARY_PATH="/opt/openssl/lib64"
	export PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig"
fi

openssl version

exec $*

