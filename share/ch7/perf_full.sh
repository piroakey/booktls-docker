#!/bin/bash

count=0
elapsed=0

start_time=`date +%s`

while true
do
  openssl s_client -connect booktls-server:10443 -tls1_2 -CAfile ca.pem <<< "Q" > /dev/null 2>&1
  ((count++))

  now=`date +%s`
  elapsed=$((now - start_time))

  if [ $elapsed -gt 30 ]; then
    break
  fi
done

echo "TLS1.2 full-handshake: ${count} connections in ${elapsed} real seconds"

sleep 3

count=0
elapsed=0

start_time=`date +%s`

while true
do
  openssl s_client -connect booktls-server:10443 -tls1_3 -CAfile ca.pem <<< "Q" > /dev/null 2>&1
  ((count++))

  now=`date +%s`
  elapsed=$((now - start_time))

  if [ $elapsed -gt 30 ]; then
    break
  fi
done

echo "TLS1.3 full-handshake: ${count} connections in ${elapsed} real seconds"
