package main

import (
"flag"
"log"
"net/http"
"time"

"github.com/casablanque-code/tollgate/internal/audit"
"github.com/casablanque-code/tollgate/internal/auth"
"github.com/casablanque-code/tollgate/internal/config"
"github.com/casablanque-code/tollgate/internal/proxy"
"github.com/casablanque-code/tollgate/internal/ratelimit"
)

func main() {
cfgPath := flag.String("config", "config.yaml", "path to config file")
flag.Parse()

cfg, err := config.Load(*cfgPath)
if err != nil {
log.Fatalf("failed to load config: %v", err)
}

logger, err := audit.New(cfg.AuditLog)
if err != nil {
log.Fatalf("failed to init audit log: %v", err)
}

verifier, err := auth.NewVerifier(cfg)
if err != nil {
log.Fatalf("failed to init verifier: %v", err)
}

var limiter *ratelimit.Limiter
if cfg.RateLimit.Enabled {
window := cfg.RateLimit.Window
if window == 0 {
window = time.Minute
}
max := cfg.RateLimit.Max
if max == 0 {
max = 100
}
limiter = ratelimit.New(max, window)
log.Printf("rate limiting enabled: %d requests per %s", max, window)
}

handler := proxy.New(cfg.Routes, verifier, logger, limiter)

log.Printf("tollgate listening on %s", cfg.Listen)
if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
log.Fatalf("server error: %v", err)
}
}
