package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type entry struct {
	timestamps []time.Time
	mu         sync.Mutex
}

type Limiter struct {
	mu       sync.RWMutex
	clients  map[string]*entry
	max      int           // максимум запросов
	window   time.Duration // за этот период
	cleanup  time.Duration // как часто чистить старые записи
}

func New(max int, window time.Duration) *Limiter {
	l := &Limiter{
		clients: make(map[string]*entry),
		max:     max,
		window:  window,
		cleanup: window * 2,
	}
	go l.cleanupLoop()
	return l
}

// Allow возвращает true если запрос разрешён
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	e, ok := l.clients[ip]
	if !ok {
		e = &entry{}
		l.clients[ip] = e
	}
	l.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// убираем старые timestamps за пределами окна
	valid := e.timestamps[:0]
	for _, t := range e.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	e.timestamps = valid

	if len(e.timestamps) >= l.max {
		return false
	}

	e.timestamps = append(e.timestamps, now)
	return true
}

// ExtractIP достаёт реальный IP из запроса.
// X-Forwarded-For намеренно игнорируется — без TLS terminator
// этот заголовок можно подделать и обойти rate limit.
// Когда появится CF Tunnel или nginx — включить обратно.
func ExtractIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanup)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-l.window)
		for ip, e := range l.clients {
			e.mu.Lock()
			active := false
			for _, t := range e.timestamps {
				if t.After(cutoff) {
					active = true
					break
				}
			}
			if !active {
				delete(l.clients, ip)
			}
			e.mu.Unlock()
		}
		l.mu.Unlock()
	}
}

// AllowSubject лимитирует по subject после аутентификации
func (l *Limiter) AllowSubject(subject string) bool {
return l.Allow("sub:" + subject)
}
