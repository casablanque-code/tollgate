# tollgate

Identity-aware Zero Trust reverse proxy. Sits in front of your self-hosted services and enforces JWT-based access control before forwarding any request.

```
                    ┌─────────────────────────────────────┐
internet / LAN ───► │  :7777  (only exposed port)         │
                    │  [tollgate]                          │
                    │  JWT auth · policy · audit · rate    │
                    └────────────┬────────────────────────┘
                                 │ tollgate-net (isolated docker network)
                    ┌────────────┴────────────────────────┐
                    │  service_a:PORT  (no host binding)   │
                    │  service_b:PORT  (no host binding)   │
                    │  service_c:PORT  (no host binding)   │
                    └─────────────────────────────────────┘
```

No service binds to the host. Direct access to any port — including from localhost — is impossible without going through tollgate. Identity is the only perimeter.

---

## Features

- **Login page** — username/password → RS256 JWT issued as HttpOnly cookie
- **Dashboard** — shows all available routes after login
- **Policy engine** — allow by subject, role, HTTP method, path pattern
- **Path stripping** — `/service/api/...` → `/api/...` before forwarding
- **Identity headers** — injects `X-Tollgate-Subject`, `X-Tollgate-Roles`, `X-Tollgate-Email`; strips `Authorization`
- **Audit log** — every request logged as JSON with decision and reason
- **Rate limiting** — sliding window per IP

---

## Quick start

```bash
git clone https://github.com/casablanque-code/tollgate
cd tollgate

# 1. Generate RSA keys for JWT signing
bash scripts/gen-keys.sh

# 2. Hash your password
bash scripts/hash-password.sh yourpassword

# 3. Configure
cp .env.example .env
# Edit .env — set ADMIN_USER, ADMIN_PASSWORD_HASH, ADMIN_EMAIL, service passwords

# 4. Start
docker compose up -d
```

Open `http://localhost:7777/login`

---

## Add a service

**1. `docker-compose.yml`** — use `expose`, not `ports`:

```yaml
my-service:
  image: someimage
  container_name: my-service
  expose:
    - "3000"
  networks:
    - tollgate-net
  restart: unless-stopped
```

**2. `config.template.yaml`** — add a route:

```yaml
- path: "/my-service"
  upstream: "http://my-service:3000"
  strip_path: true
  policy:
    allow_roles: ["admin"]
```

**3. Apply:**

```bash
docker compose up -d
```

---

## Migrate an existing service

```bash
# 1. Check volumes (data lives here, safe across container removal)
docker inspect <container> | grep -A10 Mounts

# 2. Stop and remove old container
docker stop <container> && docker rm <container>

# 3. Add to docker-compose.yml with expose + tollgate-net
# 4. Add route to config.template.yaml
docker compose up -d
```

Named volumes are not deleted by `docker rm`.

---

## Configuration

Secrets live in `.env` (gitignored). `config.template.yaml` holds routes and policy — env vars are substituted via `envsubst` at container start.

| Variable | Description |
|---|---|
| `TOLLGATE_PORT` | Host port (default: `7777`) |
| `ADMIN_USER` | Admin username |
| `ADMIN_PASSWORD_HASH` | bcrypt hash — `bash scripts/hash-password.sh yourpass` |
| `ADMIN_EMAIL` | Admin email |

See `.env.example` for all options.

---

## Policy reference

```yaml
routes:
  - path: "/api"
    upstream: "http://service:3000"
    strip_path: true
    policy:
      allow_roles: ["admin", "editor"]   # role-based
      # allow_subjects: ["alice"]        # or by identity

      rules:                             # optional: restrict by method + path
        - methods: ["GET"]
          paths: ["/*"]
        - methods: ["POST"]
          paths: ["/webhook/*"]

  - path: "/public"
    upstream: "http://service:3000"
    policy:
      public: true                       # no auth required
```

---

## Audit log

Every request produces one JSON line:

```json
{
  "time": "2026-04-12T17:35:52Z",
  "method": "POST",
  "path": "/api/users",
  "remote_ip": "127.0.0.1:41544",
  "subject": "andrew",
  "roles": ["admin"],
  "decision": "allow",
  "reason": "role match",
  "upstream": "http://service:3000",
  "status": 200
}
```

---

## TLS

Tollgate listens on plain HTTP. Put a TLS terminator in front.

**Cloudflare Tunnel** (no open ports):
```bash
cloudflared tunnel create tollgate
cloudflared tunnel route dns tollgate tollgate.yourdomain.com
```

**Caddy** (automatic Let's Encrypt):
```
tollgate.yourdomain.com {
    reverse_proxy localhost:7777
}
```

**No domain** — expose over WireGuard/AmneziaWG only. Users connect to VPN, access `http://10.x.x.x:7777/`.

---

## Philosophy

Tollgate implements one principle: never trust the network, always verify identity.

A request from localhost gets the same scrutiny as a request from the internet. Network perimeter means nothing — identity is the only perimeter. Docker network isolation ensures services are physically unreachable without going through the gateway, regardless of firewall rules.

---

## Roadmap

- [x] RS256 JWT, policy engine, audit log, rate limiting
- [x] Login page, dashboard, cookie auth
- [x] Docker Compose stack with network isolation
- [ ] mTLS client certificates
- [ ] Prometheus metrics
- [ ] Multi-upstream routing by Host header
