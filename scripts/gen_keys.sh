#!/bin/bash
set -e

if [ -f keys/private.pem ]; then
  echo "keys already exist, skipping"
  exit 0
fi

mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
echo "keys generated in keys/"
