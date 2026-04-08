package policy

import (
    "fmt"

    "github.com/casablanque-code/tollgate/internal/auth"
    "github.com/casablanque-code/tollgate/internal/config"
)

type Decision struct {
    Allowed bool
    Reason  string // для audit log: "allowed: role=admin" или "denied: subject not in allowlist"
}

// Evaluate применяет политику маршрута к claims из JWT
func Evaluate(policy config.Policy, claims *auth.Claims) Decision {
    // Публичный маршрут — пропускаем без проверки identity
    if policy.Public {
        return Decision{Allowed: true, Reason: "public route"}
    }

    // claims == nil значит токен не был предъявлен или не прошёл верификацию
    if claims == nil {
        return Decision{Allowed: false, Reason: "no valid token"}
    }

    // Проверка по subject
    if len(policy.AllowSubjects) > 0 {
        for _, s := range policy.AllowSubjects {
            if claims.Subject == s {
                return Decision{Allowed: true, Reason: fmt.Sprintf("allowed: subject=%s", s)}
            }
        }
        return Decision{
            Allowed: false,
            Reason:  fmt.Sprintf("denied: subject %q not in allowlist", claims.Subject),
        }
    }

    // Проверка по ролям
    if len(policy.AllowRoles) > 0 {
        for _, allowedRole := range policy.AllowRoles {
            for _, claimRole := range claims.Roles {
                if claimRole == allowedRole {
                    return Decision{Allowed: true, Reason: fmt.Sprintf("allowed: role=%s", claimRole)}
                }
            }
        }
        return Decision{
            Allowed: false,
            Reason:  fmt.Sprintf("denied: no matching role (have %v)", claims.Roles),
        }
    }

    // Политика не задала ни subjects, ни roles — любой валидный JWT проходит
    return Decision{Allowed: true, Reason: fmt.Sprintf("allowed: valid token, sub=%s", claims.Subject)}
}
