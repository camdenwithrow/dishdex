package main

import (
	"os"
	"time"

	"github.com/camdenwithrow/dishdex/internal/auth"
	"github.com/camdenwithrow/dishdex/internal/config"
	"github.com/camdenwithrow/dishdex/internal/database"
	"github.com/camdenwithrow/dishdex/internal/handlers"
	"github.com/camdenwithrow/dishdex/internal/logger"
	"github.com/camdenwithrow/dishdex/internal/routes"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

func main() {
	cfg := config.LoadConfig()

	e := echo.New()

	l := logger.SetupLogger(cfg)
	logger.DisableEchoDefaultLogger(e)

	l.Info("Starting DishDex application", "port", cfg.Port, "env", cfg.Env, "base_url", cfg.BaseURL)

	db, err := database.InitDB(cfg, l)
	if err != nil {
		l.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	l.Info("Database connection established")
	if err := db.Ping(); err != nil {
		l.Error("Database ping failed", "Error", err)
		os.Exit(1)
	}

	authService := auth.NewAuthService(cfg, db, l)
	authService.StartSessionCleanup(24 * time.Hour)
	authService.SetupOAuth()

	handlers := handlers.NewHandlers(cfg, db, authService, l)
	routes.SetupRoutes(e, handlers, authService, l)

	l.Info("Server starting", "port", cfg.Port)
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}
