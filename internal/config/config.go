package config

import (
	"fmt"
	"github.com/caarlos0/env/v11"
)

type Config struct {
	ENV       string `env:"ENV" envDefault:"production"`
	DbUrl     string `env:"DB_URL"`
	PORT      string `env:"PORT"`
	JwtSecret string `env:"JWT_SECRET"`
}

func New() (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return &cfg, nil
}
