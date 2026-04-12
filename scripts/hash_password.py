#!/usr/bin/env python3
import sys
import bcrypt

password = sys.argv[1].encode()
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=10))
print(hashed.decode())
