package audit

import (
    "encoding/json"
    "io"
    "net/http"
    "os"
    "time"
)

type Entry struct {
    Time      string `json:"time"`
    Method    string `json:"method"`
    Path      string `json:"path"`
    RemoteIP  string `json:"remote_ip"`
    Subject   string `json:"subject,omitempty"`
    Roles     []string `json:"roles,omitempty"`
    Decision  string `json:"decision"`
    Reason    string `json:"reason"`
    Upstream  string `json:"upstream,omitempty"`
    Status    int    `json:"status,omitempty"`
}

type Logger struct {
    out io.Writer
}

func New(target string) (*Logger, error) {
    if target == "stdout" {
        return &Logger{out: os.Stdout}, nil
    }
    f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }
    return &Logger{out: f}, nil
}

func (l *Logger) Log(r *http.Request, subject string, roles []string, decision, reason, upstream string, status int) {
    entry := Entry{
        Time:     time.Now().UTC().Format(time.RFC3339),
        Method:   r.Method,
        Path:     r.URL.Path,
        RemoteIP: r.RemoteAddr,
        Subject:  subject,
        Roles:    roles,
        Decision: decision,
        Reason:   reason,
        Upstream: upstream,
        Status:   status,
    }
    b, _ := json.Marshal(entry)
    b = append(b, '\n')
    _, _ = l.out.Write(b)
}
