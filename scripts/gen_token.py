#!/usr/bin/env python3
import argparse, base64, json, hmac, hashlib, time

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

parser = argparse.ArgumentParser()
parser.add_argument("--secret", required=True)
parser.add_argument("--sub", default="user1")
parser.add_argument("--email", default="")
parser.add_argument("--roles", default="admin")
parser.add_argument("--exp", type=int, default=3600)
args = parser.parse_args()

header  = b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
payload = b64(json.dumps({
    "sub":   args.sub,
    "email": args.email,
    "roles": args.roles.split(","),
    "exp":   int(time.time()) + args.exp
}).encode())

sig = b64(hmac.new(
    args.secret.encode(),
    f"{header}.{payload}".encode(),
    hashlib.sha256
).digest())

print(f"{header}.{payload}.{sig}")
