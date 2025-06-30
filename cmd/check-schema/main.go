package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/camdenwithrow/dishdex/internal/config"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Connect to database
	dbUrl := cfg.DatabaseURL
	dbToken := os.Getenv("TURSO_AUTH_TOKEN")

	if dbToken == "" {
		log.Fatal("TURSO_AUTH_TOKEN is required")
	}

	dbUrlFull := dbUrl + "?authToken=" + dbToken
	db, err := sql.Open("libsql", dbUrlFull)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Check if recipes table exists
	var tableExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='recipes')").Scan(&tableExists)
	if err != nil {
		log.Fatalf("Failed to check if recipes table exists: %v", err)
	}

	if !tableExists {
		fmt.Println("❌ Recipes table does not exist")
		return
	}

	fmt.Println("✅ Recipes table exists")

	// Get table schema
	rows, err := db.Query("PRAGMA table_info(recipes)")
	if err != nil {
		log.Fatalf("Failed to get table schema: %v", err)
	}
	defer rows.Close()

	fmt.Println("\n📋 Recipes table schema:")
	fmt.Printf("%-5s %-15s %-15s %-8s %-8s %-8s\n", "CID", "Name", "Type", "NotNull", "DfltValue", "PK")
	fmt.Println("----------------------------------------------------------------")

	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dfltValue sql.NullString

		err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk)
		if err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}

		dflt := "NULL"
		if dfltValue.Valid {
			dflt = dfltValue.String
		}

		fmt.Printf("%-5d %-15s %-15s %-8d %-8s %-8d\n", cid, name, typ, notNull, dflt, pk)
	}

	// Check migration version
	var version int
	err = db.QueryRow("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("\n❌ No migration version found")
		} else {
			fmt.Printf("\n❌ Failed to get migration version: %v\n", err)
		}
	} else {
		fmt.Printf("\n✅ Current migration version: %d\n", version)
	}
}
