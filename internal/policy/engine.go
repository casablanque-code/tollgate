package policy

import (
    "fmt"
    "net/http"
    "path"
    "strings"

    "github.com/casablanque-code/tollgate/internal/auth"
    "github.com/casablanque-code/tollgate/internal/config"
)

type Decision struct {
    Allowed bool
    Reason  string
}

func Evaluate(policy config.Policy, claims *auth.Claims, r *http.Request) Decision {
    if policy.Public {
        return Decision{Allowed: true, Reason: "public route"}
    }

    if claims == nil {
        return Decision{Allowed: false, Reason: "no valid token"}
    }

    // проверка identity
    identityOk, identityReason := checkIdentity(policy, claims)
    if !identityOk {
        return Decision{Allowed: false, Reason: identityReason}
    }

    // проверка rules (method + path)
    if len(policy.Rules) > 0 {
        ruleOk, ruleReason := checkRules(policy.Rules, r)
        if !ruleOk {
            return Decision{Allowed: false, Reason: ruleReason}
        }
    }

    return Decision{Allowed: true, Reason: identityReason}
}

func checkIdentity(policy config.Policy, claims *auth.Claims) (bool, string) {
    if len(policy.AllowSubjects) > 0 {
        for _, s := range policy.AllowSubjects {
            if claims.Subject == s {
                return true, fmt.Sprintf("allowed: subject=%s", s)
            }
        }
        return false, fmt.Sprintf("denied: subject %q not in allowlist", claims.Subject)
    }

    if len(policy.AllowRoles) > 0 {
        for _, allowedRole := range policy.AllowRoles {
            for _, claimRole := range claims.Roles {
                if claimRole == allowedRole {
                    return true, fmt.Sprintf("allowed: role=%s", claimRole)
                }
            }
        }
        return false, fmt.Sprintf("denied: no matching role (have %v)", claims.Roles)
    }

    return true, fmt.Sprintf("allowed: valid token, sub=%s", claims.Subject)
}

func checkRules(rules []config.Rule, r *http.Request) (bool, string) {
    for _, rule := range rules {
        if matchesMethod(rule.Methods, r.Method) && matchesPath(rule.Paths, r.URL.Path) {
            return true, fmt.Sprintf("allowed: rule match method=%s path=%s", r.Method, r.URL.Path)
        }
    }
    return false, fmt.Sprintf("denied: no rule allows method=%s path=%s", r.Method, r.URL.Path)
}

func matchesMethod(methods []string, method string) bool {
    if len(methods) == 0 {
        return true
    }
    for _, m := range methods {
        if strings.EqualFold(m, method) {
            return true
        }
    }
    return false
}

func matchesPath(patterns []string, urlPath string) bool {
    if len(patterns) == 0 {
        return true
    }
    for _, pattern := range patterns {
        // поддержка glob: /webhook/* матчит /webhook/abc
        matched, err := path.Match(pattern, urlPath)
        if err == nil && matched {
            return true
        }
        // prefix match: /api матчит /api/users
        if strings.HasPrefix(urlPath, strings.TrimSuffix(pattern, "*")) {
            return true
        }
    }
    return false
}
