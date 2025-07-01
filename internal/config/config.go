package config

import (
	"log"
	"log/slog"
	"os"
	"sync"

	"github.com/joho/godotenv"
)

var (
	once sync.Once
	cfg *Config
)

type Config struct {
	Port               string
	Env                string
	LogLevel           string
	SessionSecret      string
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
	DatabaseURL        string
	BaseURL            string
}

func LoadConfig() *Config {
	if cfg != nil {
		return cfg
	}
	once.Do(func() {
		if os.Getenv("ENV") != "production" {
			err := godotenv.Load()
			if err != nil {
				log.Fatal("Failed to load config")
			}
		}

		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}

		env := os.Getenv("ENV")
		if env == "" {
			env = "development"
		}

		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:" + port

		}

		cfg = &Config{
			Port:               port,
			Env:                env,
			LogLevel:           os.Getenv("LOG_LEVEL"),
			SessionSecret:      os.Getenv("SESSION_SECRET"),
			GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			DatabaseURL:        os.Getenv("DATABASE_URL"),
			BaseURL:            baseURL,
		}
	})
	return cfg
}

func (cfg *Config) Validate(logger *slog.Logger) {
	// Validate required configuration
	if cfg.Env == "production" {
		if cfg.SessionSecret == "" || cfg.SessionSecret == "dev_secret_key" {
			logger.Error("SESSION_SECRET is required in production")
			os.Exit(1)
		}
		if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" {
			logger.Warn("GitHub OAuth credentials not configured")
		}
		if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" {
			logger.Warn("Google OAuth credentials not configured")
		}
	}
}
