# tollgate

Zero Trust reverse proxy. Sits in front of your services and enforces
identity-based access before forwarding requests.

[client] → [tollgate] → JWT verify → policy check → [upstream]
↓
audit log (JSON)

## How it works

Every request must carry a valid JWT. Tollgate verifies the token,
evaluates the policy defined per route, and either forwards the request
with injected identity headers or returns 403.

Downstream services receive:
- `X-Tollgate-Subject` — JWT `sub` claim
- `X-Tollgate-Email`   — JWT `email` claim  
- `X-Tollgate-Roles`   — comma-separated roles

The original `Authorization` header is stripped before forwarding.

## Quick start

**1. Clone and configure**
```bash
git clone https://github.com/casablanque-code/tollgate
cd tollgate
cp config.example.yaml config.yaml
# edit config.yaml — set jwt_secret and your upstreams
```

**2. Run with Docker Compose**
```bash
docker compose up
```

**3. Generate a test token**
```bash
python3 scripts/gen_token.py --secret "your-secret" --sub "user1" --roles "admin"
```

**4. Test**
```bash
TOKEN="<paste token here>"

# allowed
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/demo/get

# denied — no token
curl http://localhost:8080/demo/get
```

## Policy config
```yaml
routes:
  - path: "/admin"
    upstream: "http://localhost:9000"
    policy:
      allow_roles: ["admin"]        # role-based

  - path: "/api"
    upstream: "http://localhost:3000"
    policy:
      allow_subjects: ["svc-worker"] # specific identity

  - path: "/health"
    upstream: "http://localhost:3000"
    policy:
      public: true                   # no auth required
```

## Audit log

Every request produces a structured JSON entry:
```json
{
  "time": "2026-04-09T10:00:00Z",
  "method": "GET",
  "path": "/admin",
  "remote_ip": "127.0.0.1:54321",
  "subject": "user1",
  "roles": ["admin"],
  "decision": "allow",
  "reason": "allowed: role=admin",
  "upstream": "http://localhost:9000",
  "status": 200
}
```

## Roadmap

- [x] v0.1 — JWT verify, YAML policy, audit log, reverse proxy
- [ ] v0.2 — mTLS client certificates
- [ ] v0.3 — Prometheus metrics (`/metrics`)
- [ ] v0.4 — Multi-upstream routing by Host header

## Philosophy

Tollgate implements the core Zero Trust principle: **never trust the
network, always verify identity**. Even requests from localhost go
through the same auth pipeline.
