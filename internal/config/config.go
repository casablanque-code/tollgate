package config

import (
"fmt"
"os"

"gopkg.in/yaml.v3"
)

type Config struct {
Listen   string     `yaml:"listen"`
Auth     AuthConfig `yaml:"auth"`
Routes   []Route    `yaml:"routes"`
AuditLog string     `yaml:"audit_log"`
}

type AuthConfig struct {
JWTSecret        string `yaml:"jwt_secret"`
JWTPublicKeyFile string `yaml:"jwt_public_key_file"`
Issuer           string `yaml:"issuer"`
Audience         string `yaml:"audience"`
}

type Route struct {
Host       string `yaml:"host"`
PathPrefix string `yaml:"path"`
Upstream   string `yaml:"upstream"`
StripPath  bool   `yaml:"strip_path"`
Policy     Policy `yaml:"policy"`
}

type Policy struct {
AllowSubjects []string `yaml:"allow_subjects"`
AllowRoles    []string `yaml:"allow_roles"`
Public        bool     `yaml:"public"`
}

func (c *Config) GetAuth() (secret, pubKeyFile, issuer, audience string) {
return c.Auth.JWTSecret, c.Auth.JWTPublicKeyFile, c.Auth.Issuer, c.Auth.Audience
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
