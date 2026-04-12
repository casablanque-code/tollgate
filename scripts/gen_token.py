#!/usr/bin/env python3
import argparse, base64, json, hmac, hashlib, time

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def compact(d):
    return json.dumps(d, separators=(',', ':')).encode()

parser = argparse.ArgumentParser()
parser.add_argument("--secret", default="")
parser.add_argument("--private-key", default="")
parser.add_argument("--sub", default="user1")
parser.add_argument("--email", default="")
parser.add_argument("--roles", default="admin")
parser.add_argument("--issuer", default="")
parser.add_argument("--audience", default="")
parser.add_argument("--exp", type=int, default=3600)
args = parser.parse_args()

payload_data = {
    "sub":   args.sub,
    "email": args.email,
    "roles": args.roles.split(","),
    "exp":   int(time.time()) + args.exp,
}
if args.issuer:
    payload_data["iss"] = args.issuer
if args.audience:
    payload_data["aud"] = args.audience

if args.private_key:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    with open(args.private_key, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    header  = b64(compact({"alg":"RS256","typ":"JWT"}))
    payload = b64(compact(payload_data))
    sig_input = f"{header}.{payload}".encode()
    sig = b64(private_key.sign(sig_input, padding.PKCS1v15(), hashes.SHA256()))
    print(f"{header}.{payload}.{sig}")
else:
    header  = b64(compact({"alg":"HS256","typ":"JWT"}))
    payload = b64(compact(payload_data))
    sig_input = f"{header}.{payload}".encode()
    sig = b64(hmac.new(args.secret.encode(), sig_input, hashlib.sha256).digest())
    print(f"{header}.{payload}.{sig}")
