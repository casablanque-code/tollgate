package proxy

import (
"net/http"
"net/http/httputil"
"net/url"
"strings"

"github.com/casablanque-code/tollgate/internal/audit"
"github.com/casablanque-code/tollgate/internal/auth"
"github.com/casablanque-code/tollgate/internal/config"
"github.com/casablanque-code/tollgate/internal/policy"
)

type Handler struct {
routes   []config.Route
verifier *auth.Verifier
logger   *audit.Logger
}

func New(routes []config.Route, v *auth.Verifier, l *audit.Logger) *Handler {
return &Handler{routes: routes, verifier: v, logger: l}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
route := h.matchRoute(r)
if route == nil {
http.Error(w, "not found", http.StatusNotFound)
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

dec := policy.Evaluate(route.Policy, claims, r)

if !dec.Allowed {
h.logger.Log(r, sub, roles, "deny", dec.Reason, route.Upstream, http.StatusForbidden)
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
