package login

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/casablanque-code/tollgate/internal/config"
)

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>tollgate</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f0f0f;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    .card {
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 40px;
      width: 100%;
      max-width: 380px;
    }
    .logo {
      font-size: 20px;
      font-weight: 600;
      color: #fff;
      margin-bottom: 8px;
      letter-spacing: -0.5px;
    }
    .subtitle {
      font-size: 13px;
      color: #666;
      margin-bottom: 32px;
    }
    label {
      display: block;
      font-size: 12px;
      color: #888;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    input {
      width: 100%;
      padding: 10px 14px;
      background: #111;
      border: 1px solid #2a2a2a;
      border-radius: 8px;
      color: #fff;
      font-size: 14px;
      margin-bottom: 16px;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus { border-color: #444; }
    button {
      width: 100%;
      padding: 11px;
      background: #fff;
      color: #000;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: opacity 0.15s;
      margin-top: 4px;
    }
    button:hover { opacity: 0.85; }
    .error {
      font-size: 13px;
      color: #e05555;
      margin-bottom: 16px;
      padding: 10px 14px;
      background: rgba(224,85,85,0.1);
      border-radius: 8px;
      border: 1px solid rgba(224,85,85,0.2);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">tollgate</div>
    <div class="subtitle">Zero Trust proxy — sign in to continue</div>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" autofocus required>
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required>
      <input type="hidden" name="redirect" value="{{.Redirect}}">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`

var tmpl = template.Must(template.New("login").Parse(loginHTML))

type Handler struct {
	users      []config.User
	privateKey interface{}
	issuer     string
	audience   string
	expiry     time.Duration
}

func New(users []config.User, privateKey interface{}, issuer, audience string) *Handler {
	return &Handler{
		users:    users,
		privateKey: privateKey,
		issuer:   issuer,
		audience: audience,
		expiry:   24 * time.Hour,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.showForm(w, r, "")
	case http.MethodPost:
		h.handleLogin(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) showForm(w http.ResponseWriter, r *http.Request, errMsg string) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]string{
		"Error":    errMsg,
		"Redirect": redirect,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	redirect := r.FormValue("redirect")
	if redirect == "" || !strings.HasPrefix(redirect, "/") {
		redirect = "/"
	}

	user := h.findUser(username)
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		h.showForm(w, r, "Invalid username or password")
		return
	}

	token, err := h.issueToken(user)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "tollgate_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(h.expiry),
	})

	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (h *Handler) findUser(username string) *config.User {
	for i := range h.users {
		if h.users[i].Username == username {
			return &h.users[i]
		}
	}
	return nil
}

func (h *Handler) issueToken(user *config.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.Username,
		"email": user.Email,
		"roles": user.Roles,
		"iss":   h.issuer,
		"aud":   []string{h.audience},
		"exp":   time.Now().Add(h.expiry).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(h.privateKey)
}
