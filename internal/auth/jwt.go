package auth

import (
    "errors"
    "fmt"
    "net/http"
    "strings"

    "github.com/golang-jwt/jwt/v5"
)

// Claims — наши кастомные поля поверх стандартных JWT claims
type Claims struct {
    jwt.RegisteredClaims
    Roles  []string `json:"roles"`
    Email  string   `json:"email"`
}

type Verifier struct {
    secret    []byte      // для HS256
    publicKey interface{} // для RS256 (rsa.PublicKey)
}

func NewVerifier(secret string) *Verifier {
    return &Verifier{secret: []byte(secret)}
}

// FromRequest извлекает и верифицирует JWT из заголовка Authorization
func (v *Verifier) FromRequest(r *http.Request) (*Claims, error) {
    raw, err := extractBearer(r)
    if err != nil {
        return nil, err
    }
    return v.Verify(raw)
}

func (v *Verifier) Verify(tokenStr string) (*Claims, error) {
    claims := &Claims{}

    token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
        // Проверяем что алгоритм не подменили на "none"
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return v.secret, nil
    })

    if err != nil {
        return nil, fmt.Errorf("jwt verify: %w", err)
    }
    if !token.Valid {
        return nil, errors.New("jwt: token invalid")
    }

    return claims, nil
}

func extractBearer(r *http.Request) (string, error) {
    header := r.Header.Get("Authorization")
    if header == "" {
        return "", errors.New("authorization header missing")
    }
    parts := strings.SplitN(header, " ", 2)
    if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
        return "", errors.New("authorization: expected 'Bearer <token>'")
    }
    return parts[1], nil
}
