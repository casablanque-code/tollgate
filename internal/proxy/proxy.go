package proxy

import (
"net/http"
"net/http/httputil"
"net/url"
"strings"
"path"

"github.com/casablanque-code/tollgate/internal/audit"
"github.com/casablanque-code/tollgate/internal/auth"
"github.com/casablanque-code/tollgate/internal/config"
"github.com/casablanque-code/tollgate/internal/policy"
"github.com/casablanque-code/tollgate/internal/ratelimit"
)

// checkCSRF проверяет Origin/Referer для mutating методов
func checkCSRF(r *http.Request) bool {
    method := r.Method
    if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
        return true
    }
    // API клиенты с Bearer токеном — не браузер, CSRF не применяется
    if r.Header.Get("Authorization") != "" {
        return true
    }
    // cookie-based запросы — проверяем Origin/Referer
    host := r.Host
    origin := r.Header.Get("Origin")
    if origin != "" {
        return origin == "http://"+host || origin == "https://"+host
    }
    referer := r.Header.Get("Referer")
    if referer != "" {
        return strings.HasPrefix(referer, "http://"+host) ||
            strings.HasPrefix(referer, "https://"+host)
    }
    // нет ни Origin ни Referer — блокируем
    return false
}

type Handler struct {
routes   []config.Route
verifier *auth.Verifier
logger   *audit.Logger
limiter  *ratelimit.Limiter
}

func New(routes []config.Route, v *auth.Verifier, l *audit.Logger, limiter *ratelimit.Limiter) *Handler {
return &Handler{routes: routes, verifier: v, logger: l, limiter: limiter}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
route := h.matchRoute(r)
if route == nil {
http.Error(w, "not found", http.StatusNotFound)
return
}

// Security: удаляем входящие identity headers — клиент не может их подделать
r.Header.Del("X-Tollgate-Subject")
r.Header.Del("X-Tollgate-Email")
r.Header.Del("X-Tollgate-Roles")

// нормализуем path — предотвращаем traversal атаки
r.URL.Path = path.Clean(r.URL.Path)
if r.URL.RawPath != "" {
    r.URL.RawPath = path.Clean(r.URL.RawPath)
}

// Security: удаляем method override headers — нельзя обойти method rules
r.Header.Del("X-HTTP-Method-Override")
r.Header.Del("X-Method-Override")
r.Header.Del("_method")

// Rate limiting
if h.limiter != nil {
    ip := ratelimit.ExtractIP(r)
    if !h.limiter.Allow(ip) {
        h.logger.Log(r, "", nil, "deny", "rate limit exceeded", "", http.StatusTooManyRequests)
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
}

// CSRF check для mutating методов
if !checkCSRF(r) {
    h.logger.Log(r, "", nil, "deny", "CSRF check failed", "", http.StatusForbidden)
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}

// Strip path prefix перед форвардом
if route.StripPath && route.PathPrefix != "/" {
r.URL.Path = strings.TrimPrefix(r.URL.Path, route.PathPrefix)
if r.URL.Path == "" {
r.URL.Path = "/"
}
if r.URL.RawPath != "" {
r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, route.PathPrefix)
}
}

// Auth
claims, _ := h.verifier.FromRequest(r)

// Policy
var sub string
var roles []string
if claims != nil {
sub = claims.Subject
roles = claims.Roles
}

// rate limit по subject если аутентифицирован
if h.limiter != nil && claims != nil {
    if !h.limiter.AllowSubject(claims.Subject) {
        h.logger.Log(r, sub, roles, "deny", "rate limit exceeded (subject)", "", http.StatusTooManyRequests)
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
}

dec := policy.Evaluate(route.Policy, claims, r)

if !dec.Allowed {
    h.logger.Log(r, sub, roles, "deny", dec.Reason, route.Upstream, http.StatusForbidden)
    accept := r.Header.Get("Accept")
    if strings.Contains(accept, "text/html") {
        http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusSeeOther)
        return
    }
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}

// Inject identity headers
if claims != nil {
r.Header.Set("X-Tollgate-Subject", claims.Subject)
r.Header.Set("X-Tollgate-Email", claims.Email)
if len(claims.Roles) > 0 {
r.Header.Set("X-Tollgate-Roles", strings.Join(claims.Roles, ","))
}
}
r.Header.Del("Authorization")

// Proxy
target, _ := url.Parse(route.Upstream)
proxy := httputil.NewSingleHostReverseProxy(target)
proxy.Director = func(req *http.Request) {
    req.URL.Scheme = target.Scheme
    req.URL.Host = target.Host
    req.Host = target.Host
    // не добавляем X-Forwarded-For — это задача внешнего TLS terminator
}

rw := &responseWriter{ResponseWriter: w}
proxy.ServeHTTP(rw, r)

h.logger.Log(r, sub, roles, "allow", dec.Reason, route.Upstream, rw.status)
}

func (h *Handler) matchRoute(r *http.Request) *config.Route {
for i := range h.routes {
route := &h.routes[i]
if route.Host != "" && r.Host != route.Host {
continue
}
if strings.HasPrefix(r.URL.Path, route.PathPrefix) {
return route
}
}
return nil
}

type responseWriter struct {
http.ResponseWriter
status int
}

func (rw *responseWriter) WriteHeader(code int) {
rw.status = code
rw.ResponseWriter.WriteHeader(code)
}
