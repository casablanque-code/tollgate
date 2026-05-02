#!/bin/bash
# Generate RSA key pair for Tollgate JWT signing
set -e

KEYS_DIR="$(dirname "$0")/../keys"
mkdir -p "$KEYS_DIR"

if [ -f "$KEYS_DIR/private.pem" ]; then
  echo "Keys already exist in $KEYS_DIR, skipping."
  exit 0
fi

echo "Generating RSA-2048 key pair..."
openssl genrsa -out "$KEYS_DIR/private.pem" 2048
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"
echo "Done: $KEYS_DIR/private.pem + public.pem"
