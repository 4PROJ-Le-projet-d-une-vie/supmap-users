package config

type Config struct {
	DB_URL string `env:DB_URL`
	PORT   string `env:PORT`
}

func New() (*Config, error) {
	return &Config{}, nil
}
