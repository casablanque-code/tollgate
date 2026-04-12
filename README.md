# tollgate

Identity-aware Zero Trust reverse proxy. Sits in front of your services and enforces JWT-based access control before forwarding any request.

```
[browser] → [tollgate :PORT]
                │
                ├── /login — username + password → JWT cookie
                ├── verify RS256 JWT (iss, aud, exp)
                ├── evaluate policy (subject / role / method / path)
                ├── rate limit per IP
                ├── inject identity headers
                └── forward to upstream
                         │
                    audit log (JSON)
```

Built in Go. Single binary, single config file, no external dependencies.

---

## Features

- **Login page** — username/password auth, JWT issued as `HttpOnly` cookie, no browser extension needed
- **Dashboard** — after login, shows all available services in one place
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

Keep `keys/private.pem` secret — it never leaves the server. Tollgate uses it only to sign login tokens.

### 3. Hash passwords for your users

```bash
pip3 install bcrypt
python3 scripts/hash_password.py "USER_PASSWORD"
```

### 4. Configure

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:

```yaml
listen: ":PORT"

auth:
  jwt_public_key_file: "keys/public.pem"
  jwt_private_key_file: "keys/private.pem"
  issuer: "tollgate"
  audience: "tollgate"

audit_log: "stdout"

rate_limit:
  enabled: true
  max: 100
  window: 1m

users:
  - username: "USER_NAME"
    password_hash: "$2b$10$..."   # from hash_password.py
    email: "USER_EMAIL"
    roles: ["admin"]
  - username: "USER_NAME"
    password_hash: "$2b$10$..."
    email: "USER_EMAIL"
    roles: ["employee"]

routes:
  - path: "/portainer"
    upstream: "http://localhost:9000"
    strip_path: true
    policy:
      allow_roles: ["admin"]
      rules:
        - methods: ["GET", "POST", "PUT", "PATCH"]
          paths: ["/*"]

  - path: "/app"
    upstream: "http://localhost:3000"
    strip_path: true
    policy:
      allow_roles: ["admin", "employee"]

  - path: "/health"
    upstream: "http://localhost:9000"
    policy:
      public: true
```

### 5. Build and run

```bash
go build -o tollgate ./cmd/tollgate/
./tollgate --config config.yaml
```

Open `http://localhost:PORT/` — you will be redirected to the login page.

---

## User management

Users are defined in `config.yaml`. To add a user:

**1. Generate a password hash**
```bash
python3 scripts/hash_password.py "USER_PASSWORD"
# → $2b$10$...
```

**2. Add to config.yaml**
```yaml
users:
  - username: "USER_NAME"
    password_hash: "$2b$10$..."
    email: "USER_EMAIL"
    roles: ["employee"]
```

**3. Restart tollgate**
```bash
sudo systemctl restart tollgate
```

To revoke access — remove the user from `config.yaml` and restart. No token invalidation needed — cookie expires naturally or on next restart.

Roles are arbitrary strings. Define them in `users` and reference them in route `policy`. Common patterns:

```yaml
roles: ["admin"]             # full access
roles: ["employee"]          # limited access
roles: ["admin", "employee"] # multiple roles
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

The compose stack starts tollgate and httpbin as a demo upstream. Open `http://localhost:PORT/` and sign in with the credentials from `config.example.yaml`.

---

## TLS / production deployment

Tollgate listens on plain HTTP. Put a TLS terminator in front of it.

**Option A — Cloudflare Tunnel** (recommended, no open ports)
```bash
cloudflared tunnel create tollgate
cloudflared tunnel route dns tollgate tollgate.your-domain.com
```
```yaml
# ~/.cloudflared/config.yml
tunnel: <tunnel-id>
ingress:
  - hostname: tollgate.your-domain.com
    service: http://localhost:PORT
  - service: http_status:404
```

**Option B — Caddy** (automatic Let's Encrypt)
Caddyfile
tollgate.your-domain.com {
reverse_proxy localhost:PORT
}
**Option C — nginx + certbot**
```nginx
server {
    listen 443 ssl;
    server_name tollgate.your-domain.com;
    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    location / {
        proxy_pass http://localhost:PORT;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

**Without a domain — VPN access**

If you don't have a domain, expose tollgate only over a VPN (WireGuard, AmneziaWG). Users connect to VPN, then access `http://10.x.x.x:8080/`. No open ports, no domain needed.

---

## Protecting Docker services

Bind services to `127.0.0.1` so they're only reachable through tollgate:

```bash
# before: accessible from anywhere
docker run -p 9000:9000 portainer/portainer-ce

# after: localhost only
docker run -p 127.0.0.1:9000:9000 portainer/portainer-ce
```

---

## Policy reference

```yaml
routes:
  - path: "/api"
    upstream: "http://localhost:3000"
    strip_path: true
    policy:
      allow_subjects: ["USER_NAME"]          # specific identity
      # or
      allow_roles: ["admin", "editor"]   # role-based

      # optional: restrict by method and path
      rules:
        - methods: ["GET"]
          paths: ["/*"]
        - methods: ["POST"]
          paths: ["/webhook/*"]

  - path: "/public"
    upstream: "http://localhost:3000"
    policy:
      public: true                       # no auth required
```

Rules are evaluated after identity check. If `rules` is empty — any method and path is allowed. If set — request must match at least one rule.

---

## Identity headers

Tollgate strips `Authorization` and injects:

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
  "subject": "USER_NAME",
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

## Roadmap

- [x] v0.1 — RS256 JWT, iss/aud validation, YAML policy, audit log, reverse proxy
- [x] v0.1 — method + path rules
- [x] v0.1 — sliding window rate limiting
- [x] v0.1 — login page, cookie auth, user management, dashboard
- [ ] v0.2 — mTLS client certificates
- [ ] v0.3 — Prometheus metrics (`/metrics`)
- [ ] v0.4 — multi-upstream routing by Host header

---

## Philosophy

Tollgate implements one principle: **never trust the network, always verify identity**.

A request from localhost gets the same scrutiny as a request from the internet. The network perimeter means nothing — identity is the only perimeter.
