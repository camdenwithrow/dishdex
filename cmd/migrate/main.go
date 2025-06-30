package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	"github.com/camdenwithrow/dishdex/internal/config"
	"github.com/camdenwithrow/dishdex/internal/database"
	l "github.com/camdenwithrow/dishdex/internal/logger"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

func main() {
	var (
		up      = flag.Bool("up", false, "Run all pending migrations")
		down    = flag.Bool("down", false, "Rollback the last migration")
		version = flag.Bool("version", false, "Show current migration version")
		create  = flag.String("create", "", "Create a new migration file")
	)
	flag.Parse()

	// Load configuration
	cfg := config.LoadConfig()

	// Initialize logger
	logger := l.SetupLogger(cfg)

	// Initialize database connection
	database, err := database.InitDB(cfg, logger)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Handle different commands
	switch {
	case *up:
		if err := runMigrations(database, logger); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
		fmt.Println("Migrations completed successfully")
	case *down:
		if err := rollbackMigration(database, logger); err != nil {
			log.Fatalf("Failed to rollback migration: %v", err)
		}
		fmt.Println("Migration rolled back successfully")
	case *version:
		version, err := getMigrationVersion(database)
		if err != nil {
			log.Fatalf("Failed to get migration version: %v", err)
		}
		fmt.Printf("Current migration version: %d\n", version)
	case *create != "":
		if err := createMigration(*create); err != nil {
			log.Fatalf("Failed to create migration: %v", err)
		}
		fmt.Printf("Migration '%s' created successfully\n", *create)
	default:
		fmt.Println("Usage:")
		flag.PrintDefaults()
	}
}

func runMigrations(db *sql.DB, logger *l.Logger) error {
	return database.RunMigrations(db, logger)
}

func rollbackMigration(db *sql.DB, logger *l.Logger) error {
	// This would need to be implemented in the migrations.go file
	// For now, we'll just return an error
	return fmt.Errorf("rollback not implemented yet")
}

func getMigrationVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return version, nil
}

func createMigration(name string) error {
	// This would create new migration files
	// For now, we'll just return an error
	return fmt.Errorf("create migration not implemented yet")
}
