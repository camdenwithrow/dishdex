package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/camdenwithrow/dishdex/internal/config"
	l "github.com/camdenwithrow/dishdex/internal/logger"
)

func InitDB(config *config.Config, logger *l.Logger) (*sql.DB, error) {
	dbUrl := config.DatabaseURL
	dbToken := os.Getenv("TURSO_AUTH_TOKEN")
	var db *sql.DB
	var err error

	// If no database URL is provided, use local SQLite
	if dbUrl == "" {
		dbUrl = "dishdex.db"
	}

	// Check if it's a Turso database URL (contains libsql://)
	if strings.Contains(dbUrl, "libsql://") {
		if dbToken == "" {
			return nil, fmt.Errorf("TURSO_AUTH_TOKEN is required for Turso database")
		}
		dbUrlFull := dbUrl + "?authToken=" + dbToken
		db, err = sql.Open("libsql", dbUrlFull)
		slog.Info("Connecting to Turso database", "url", dbUrl)
	} else {
		// Local SQLite database
		db, err = sql.Open("sqlite3", dbUrl)
		slog.Info("Connecting to local SQLite database", "file", dbUrl)
	}

	if err != nil {
		return nil, err
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		logger.Error("Database ping failed", "Error", err)
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	// Run database migrations
	if err := RunMigrations(db, logger); err != nil {
		logger.Error("Failed to run migrations", "error", err)
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	logger.Info("Database tables initialized successfully")
	return db, nil
}
