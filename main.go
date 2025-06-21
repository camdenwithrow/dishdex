package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/a-h/templ"
	"github.com/camdenwithrow/dishdex/templates"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/mattn/go-sqlite3"
)

type Environment string

const (
	Development Environment = "dev"
	Production  Environment = "prod"
)

type Config struct {
	Environment Environment
	Port        string
}

var (
	config *Config
	once   sync.Once
)

func loadConfig() *Config {
	once.Do(func() {
		env := getEnvironment()
		config = &Config{
			Environment: env,
			Port:        getEnv("PORT", "4444"),
		}
	})
	return config
}

func getEnvironment() Environment {
	env := os.Getenv("ENVIRONMENT")
	if env == "producation" {
		return Production
	}
	return Development
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (c *Config) IsDevelopment() bool {
	return c.Environment == Development
}

func (c *Config) IsProduction() bool {
	return c.Environment == Production
}

func connectDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "dishdex.db")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

type handler struct {
	config *Config
}

func (handler) Home() echo.HandlerFunc {
	return func(c echo.Context) error {
		return render(c, templates.Home())
	}
}

func (handler) Health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":      "healthy",
			"environment": config.Environment,
		})
	}
}

func render(c echo.Context, component templ.Component) error {
	return component.Render(c.Request().Context(), c.Response().Writer)
}

func main() {
	cfg := loadConfig()

	db, err := connectDatabase()
	if err != nil {
		log.Fatal("Failed to connect to db ", err)
	}
	defer db.Close()

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Routes
	h := handler{config: cfg}
	e.GET("/", h.Home())
	e.GET("/health", h.Health())

	// Start Server
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}
