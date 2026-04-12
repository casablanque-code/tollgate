package main

import (
	"flag"
	"log"
	"net/http"
	"time"
	"fmt"

	"github.com/casablanque-code/tollgate/internal/audit"
	"github.com/casablanque-code/tollgate/internal/auth"
	"github.com/casablanque-code/tollgate/internal/config"
	"github.com/casablanque-code/tollgate/internal/login"
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

	mux := http.NewServeMux()

	// login handler — нужен приватный ключ
	if cfg.Auth.JWTPrivateKeyFile != "" && len(cfg.Users) > 0 {
		privateKey, err := auth.LoadPrivateKey(cfg.Auth.JWTPrivateKeyFile)
		if err != nil {
			log.Fatalf("failed to load private key: %v", err)
		}
		loginHandler := login.New(cfg.Users, privateKey, cfg.Auth.Issuer, cfg.Auth.Audience)
		mux.HandleFunc("/login", loginHandler.ServeHTTP)
		mux.HandleFunc("/login/", loginHandler.ServeHTTP)
		log.Printf("login page enabled at /login (%d users)", len(cfg.Users))
	}

	// proxy handler для всего остального
	proxyHandler := proxy.New(cfg.Routes, verifier, logger, limiter)

	// редирект на /login если нет токена
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/logout" {
        http.SetCookie(w, &http.Cookie{
            Name:    "tollgate_token",
            Value:   "",
            Path:    "/",
            Expires: time.Unix(0, 0),
            MaxAge:  -1,
        })
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    if r.URL.Path == "/" {
        // проверяем токен
        _, err := verifier.FromRequest(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        // дашборд
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>tollgate</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{min-height:100vh;background:#0f0f0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#fff;padding:40px}
    h1{font-size:20px;font-weight:600;margin-bottom:8px}
    .sub{color:#666;font-size:13px;margin-bottom:40px}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;max-width:800px}
    a{display:block;padding:20px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;color:#fff;text-decoration:none;font-size:15px;font-weight:500;transition:border-color 0.15s}
    a:hover{border-color:#444}
    .meta{font-size:12px;color:#666;margin-top:4px}
    .logout{position:fixed;top:20px;right:20px;font-size:13px;color:#666;text-decoration:none}
    .logout:hover{color:#fff}
  </style>
</head>
<body>
  <a href="/logout" class="logout">sign out</a>
  <h1>tollgate</h1>
  <div class="sub">select a service</div>
  <div class="grid">`)
        for _, route := range cfg.Routes {
            if !route.Policy.Public {
                fmt.Fprintf(w, `<a href="%s/"><span>%s</span><div class="meta">%s</div></a>`,
                    route.PathPrefix, route.PathPrefix[1:], route.Upstream)
            }
        }
        fmt.Fprintf(w, `</div></body></html>`)
        return
    }
    proxyHandler.ServeHTTP(w, r)
})

	log.Printf("tollgate listening on %s", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
