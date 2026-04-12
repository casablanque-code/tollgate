package main

import (
"flag"
"log"
"net/http"

"github.com/casablanque-code/tollgate/internal/audit"
"github.com/casablanque-code/tollgate/internal/auth"
"github.com/casablanque-code/tollgate/internal/config"
"github.com/casablanque-code/tollgate/internal/proxy"
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

handler := proxy.New(cfg.Routes, verifier, logger)

log.Printf("tollgate listening on %s", cfg.Listen)
if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
log.Fatalf("server error: %v", err)
}
}
