# tollgate

Identity-aware Zero Trust reverse proxy. Sits in front of your services and enforces JWT-based access control before forwarding any request. [client] → [tollgate :8080]
│
├── verify RS256 JWT (iss, aud, exp)
├── evaluate policy (subject / role / method / path)
├── rate limit per IP
├── inject identity headers
└── forward to upstream
│
audit log (JSON) Built in Go. Single binary, single config file, no external dependencies.

---

## Features

- **RS256 JWT verification** — asymmetric keys, tollgate holds only the public key and cannot forge tokens
- **Issuer / audience validation** — rejects tokens from other services
- **Identity-aware policy** — allow by subject, role, HTTP method, and path pattern
- **Path stripping** — `/portainer/api/...` → `/api/...` before forwarding
- **Identity header injection** — downstream services receive `X-Tollgate-Subject`, `X-Tollgate-Roles`, `X-Tollgate-Email`; original `Authorization` header is stripped
- **Structured audit log** — every request logged as JSON with decision and reason
- **Rate limiting** — sliding window per IP, configurable max requests and window

---

## Quick start

### 1. Clone

```bash
git clone https://github.com/casablanque-code/tollgate
cd tollgate
```

### 2. Generate RSA key pair

```bash
mkdir keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

Keep `keys/private.pem` secret — it never leaves the machine that issues tokens. Tollgate only needs `keys/public.pem`.

### 3. Configure

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:

```yaml
listen: ":8080"

auth:
  jwt_public_key_file: "keys/public.pem"
  issuer: "tollgate"
  audience: "tollgate"

audit_log: "stdout"

rate_limit:
  enabled: true
  max: 100
  window: 1m

routes:
  - path: "/portainer"
    upstream: "http://localhost:9000"
    strip_path: true
    policy:
      allow_subjects: ["alice"]
      rules:
        - methods: ["GET", "POST", "PUT", "PATCH"]
          paths: ["/*"]

  - path: "/health"
    upstream: "http://localhost:9000"
    policy:
      public: true
```

### 4. Build and run

```bash
go build -o tollgate ./cmd/tollgate/
./tollgate --config config.yaml
```

### 5. Generate a token

```bash
pip3 install cryptography
python3 scripts/gen_token.py \
  --private-key keys/private.pem \
  --sub "alice" \
  --roles "admin" \
  --issuer "tollgate" \
  --audience "tollgate" \
  --exp 31536000
```

### 6. Test

```bash
TOKEN="<paste token here>"

# allowed
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/portainer/

# denied — no token
curl http://localhost:8080/portainer/

# denied — wrong method (if rules configured)
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:8080/portainer/api/users/1
```

---

## Run as systemd service

```bash
sudo nano /etc/systemd/system/tollgate.service
```

```ini
[Unit]
Description=tollgate zero trust proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/tollgate
ExecStart=/opt/tollgate/tollgate --config /opt/tollgate/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable tollgate
sudo systemctl start tollgate
```

---

## Run with Docker Compose

```bash
docker compose up
```

The compose stack starts tollgate and httpbin as a demo upstream. Use `config.example.yaml` as the config — it routes `/demo` to httpbin.

---

## Policy reference

```yaml
routes:
  - path: "/api"
    upstream: "http://localhost:3000"
    strip_path: true
    policy:
      # allow by JWT subject
      allow_subjects: ["alice", "bob"]

      # or allow by role claim
      allow_roles: ["admin", "editor"]

      # optional: restrict by HTTP method and path
      rules:
        - methods: ["GET"]
          paths: ["/*"]
        - methods: ["POST"]
          paths: ["/webhook/*"]

  - path: "/public"
    upstream: "http://localhost:3000"
    policy:
      public: true   # no token required
```

Rules are evaluated after identity check. If `rules` is empty, any method and path is allowed for the authenticated identity. If `rules` is set, the request must match at least one rule.

---

## Identity headers

Tollgate strips the original `Authorization` header and injects:

| Header | Value |
|---|---|
| `X-Tollgate-Subject` | JWT `sub` claim |
| `X-Tollgate-Email` | JWT `email` claim |
| `X-Tollgate-Roles` | comma-separated roles |

Downstream services can trust these headers — they are set by tollgate, not the client.

---

## Audit log

Every request produces one JSON line:

```json
{
  "time": "2026-04-12T17:35:52Z",
  "method": "DELETE",
  "path": "/api/users/1",
  "remote_ip": "127.0.0.1:41544",
  "subject": "alice",
  "roles": ["admin"],
  "decision": "deny",
  "reason": "denied: no rule allows method=DELETE path=/api/users/1",
  "upstream": "http://localhost:9000",
  "status": 403
}
```

Set `audit_log: "stdout"` or `audit_log: "/var/log/tollgate/audit.log"`.

---

## Rate limiting

Sliding window per client IP. Returns `429 Too Many Requests` when exceeded.

```yaml
rate_limit:
  enabled: true
  max: 100      # requests
  window: 1m    # per minute
```

---

## Protecting Docker services

If your services are exposed on `0.0.0.0`, restrict them to localhost and route through tollgate instead:

```bash
# before: accessible from anywhere
docker run -p 9000:9000 portainer/portainer-ce

# after: localhost only, tollgate is the only entry point
docker run -p 127.0.0.1:9000:9000 portainer/portainer-ce
```

---

## Roadmap

- [x] v0.1 — RS256 JWT, iss/aud validation, YAML policy, audit log, reverse proxy
- [x] v0.1 — method + path rules
- [x] v0.1 — sliding window rate limiting
- [ ] v0.2 — mTLS client certificates
- [ ] v0.3 — Prometheus metrics (`/metrics`)
- [ ] v0.4 — Multi-upstream routing by Host header
- [ ] v0.5 — Login page with cookie-based auth (no browser extension needed)

---

## Philosophy

Tollgate implements one principle: **never trust the network, always verify identity**.

A request from localhost gets the same scrutiny as a request from the internet. The network perimeter means nothing — identity is the only perimeter.
