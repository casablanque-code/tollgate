package auth

import (
"crypto/rsa"
"errors"
"fmt"
"net/http"
"os"
"strings"

"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
jwt.RegisteredClaims
Roles []string `json:"roles"`
Email string   `json:"email"`
}

type AuthConfig interface {
GetAuth() (secret, pubKeyFile, issuer, audience string)
}

type Verifier struct {
secret    []byte
publicKey *rsa.PublicKey
issuer    string
audience  string
}

func NewVerifier(cfg AuthConfig) (*Verifier, error) {
secret, pubKeyFile, issuer, audience := cfg.GetAuth()
v := &Verifier{issuer: issuer, audience: audience}

if pubKeyFile != "" {
data, err := os.ReadFile(pubKeyFile)
if err != nil {
return nil, fmt.Errorf("auth: read public key: %w", err)
}
key, err := jwt.ParseRSAPublicKeyFromPEM(data)
if err != nil {
return nil, fmt.Errorf("auth: parse public key: %w", err)
}
v.publicKey = key
return v, nil
}

if secret != "" {
v.secret = []byte(secret)
return v, nil
}

return nil, errors.New("auth: either jwt_secret or jwt_public_key_file must be set")
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: read private key: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("auth: parse private key: %w", err)
	}
	return key, nil
}

func (v *Verifier) FromRequest(r *http.Request) (*Claims, error) {
	// сначала пробуем Authorization header
	if raw, err := extractBearer(r); err == nil {
		return v.Verify(raw)
	}
	// потом cookie
	if cookie, err := r.Cookie("tollgate_token"); err == nil {
		return v.Verify(cookie.Value)
	}
	return nil, errors.New("no token provided")
}

func (v *Verifier) Verify(tokenStr string) (*Claims, error) {
claims := &Claims{}

token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
if v.publicKey != nil {
if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
return nil, fmt.Errorf("expected RS256, got %v", t.Header["alg"])
}
return v.publicKey, nil
}
if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
return nil, fmt.Errorf("expected HS256, got %v", t.Header["alg"])
}
return v.secret, nil
})

if err != nil {
return nil, fmt.Errorf("jwt verify: %w", err)
}
if !token.Valid {
return nil, errors.New("jwt: token invalid")
}

if v.issuer != "" {
iss, _ := claims.GetIssuer()
if iss != v.issuer {
return nil, fmt.Errorf("jwt: issuer mismatch: got %q, want %q", iss, v.issuer)
}
}

if v.audience != "" {
aud, _ := claims.GetAudience()
found := false
for _, a := range aud {
if a == v.audience {
found = true
break
}
}
if !found {
return nil, fmt.Errorf("jwt: audience mismatch: got %v, want %q", aud, v.audience)
}
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
