package config

import (
    "fmt"
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

type Config struct {
    Listen   string     `yaml:"listen"`    // ":8080"
    TLS      TLSConfig  `yaml:"tls"`
    Auth     AuthConfig `yaml:"auth"`
    Routes   []Route    `yaml:"routes"`
    AuditLog string     `yaml:"audit_log"` // путь к файлу или "stdout"
}

type TLSConfig struct {
    Enabled  bool   `yaml:"enabled"`
    CertFile string `yaml:"cert_file"`
    KeyFile  string `yaml:"key_file"`
}

type AuthConfig struct {
    // JWT секрет (HS256) или путь к публичному ключу (RS256)
    JWTSecret     string        `yaml:"jwt_secret"`
    JWTPublicKey  string        `yaml:"jwt_public_key"`
    TokenExpiry   time.Duration `yaml:"token_expiry"`
}

type Route struct {
    // Что защищаем
    Host     string `yaml:"host"`      // опционально: "portainer.local"
    PathPrefix string `yaml:"path"`    // "/api", "/"

    // Куда форвардим
    Upstream string `yaml:"upstream"`  // "http://localhost:9000"
    //path
    StripPath  bool   `yaml:"strip_path"`
    // Политика доступа
    Policy   Policy `yaml:"policy"`
}

type Policy struct {
    // Список разрешённых subject'ов из JWT (поле "sub")
    AllowSubjects []string `yaml:"allow_subjects"`
    // Список разрешённых ролей (поле "roles" в JWT claims)
    AllowRoles    []string `yaml:"allow_roles"`
    // Если пусто — разрешён любой валидный JWT
    Public        bool     `yaml:"public"`
}

func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("config: read file: %w", err)
    }

    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("config: parse yaml: %w", err)
    }

    if err := cfg.validate(); err != nil {
        return nil, fmt.Errorf("config: validation: %w", err)
    }

    return &cfg, nil
}

func (c *Config) validate() error {
    if c.Listen == "" {
        c.Listen = ":8080"
    }
    if len(c.Routes) == 0 {
        return fmt.Errorf("no routes defined")
    }
    for i, r := range c.Routes {
        if r.Upstream == "" {
            return fmt.Errorf("route[%d]: upstream is required", i)
        }
        if r.PathPrefix == "" {
            c.Routes[i].PathPrefix = "/"
        }
    }
    if c.AuditLog == "" {
        c.AuditLog = "stdout"
    }
    return nil
}
