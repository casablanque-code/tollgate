#!/bin/bash
# Generate bcrypt password hash for .env
# Usage: ./scripts/hash-password.sh yourpassword
set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <password>"
  exit 1
fi

if command -v htpasswd &>/dev/null; then
  htpasswd -bnBC 10 "" "$1" | tr -d ':\n'
  echo
elif command -v python3 &>/dev/null; then
  python3 -c "import bcrypt; print(bcrypt.hashpw(b'$1', bcrypt.gensalt(rounds=10)).decode())"
else
  echo "Install apache2-utils (htpasswd) or python3-bcrypt"
  exit 1
fi
