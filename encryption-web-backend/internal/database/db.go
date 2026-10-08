package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	Driver string
}

func Connect() (*DB, error) {
	dbType := strings.ToLower(os.Getenv("DB_TYPE"))
	if dbType == "" {
		// Default to postgres if DB_HOST or DATABASE_URL is set, else sqlite
		if os.Getenv("DATABASE_URL") != "" || os.Getenv("DB_HOST") != "" {
			dbType = "postgres"
		} else {
			dbType = "sqlite"
		}
	}

	var db *sql.DB
	var err error

	if dbType == "postgres" {
		connStr := os.Getenv("DATABASE_URL")
		if connStr == "" {
			host := getEnv("DB_HOST", "localhost")
			port := getEnv("DB_PORT", "5432")
			user := getEnv("DB_USER", "postgres")
			pass := getEnv("DB_PASSWORD", "postgres")
			name := getEnv("DB_NAME", "encryption_db")
			ssl := getEnv("DB_SSLMODE", "disable")
			connStr = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
				host, port, user, pass, name, ssl)
		}

		log.Printf("Connecting to PostgreSQL...")
		// Retry a few times in case postgres container is warming up
		for attempts := 1; attempts <= 5; attempts++ {
			db, err = sql.Open("postgres", connStr)
			if err == nil {
				if pingErr := db.Ping(); pingErr == nil {
					break
				} else {
					err = pingErr
				}
			}
			log.Printf("Postgres ping failed (attempt %d/5): %v. Retrying in 2s...", attempts, err)
			time.Sleep(2 * time.Second)
		}

		if err != nil {
			return nil, fmt.Errorf("could not connect to postgresql: %w", err)
		}
	} else {
		dbPath := getEnv("SQLITE_PATH", "data/encryption_app.db")
		_ = os.MkdirAll("data", 0755)
		log.Printf("Connecting to SQLite at %s...", dbPath)
		db, err = sql.Open("sqlite", dbPath)
		if err != nil {
			return nil, fmt.Errorf("could not open sqlite database: %w", err)
		}
	}

	appDB := &DB{DB: db, Driver: dbType}
	if err := appDB.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return appDB, nil
}

func (db *DB) migrate() error {
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(64) PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		salt VARCHAR(128) NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`

	personalDataTable := `
	CREATE TABLE IF NOT EXISTS personal_data (
		id VARCHAR(64) PRIMARY KEY,
		user_id VARCHAR(64) NOT NULL,
		label VARCHAR(255) NOT NULL,
		aes_cipher_hex TEXT NOT NULL,
		aes_duration_ns BIGINT NOT NULL,
		aes_cipher_size INT NOT NULL,
		rc4_cipher_hex TEXT NOT NULL,
		rc4_duration_ns BIGINT NOT NULL,
		rc4_cipher_size INT NOT NULL,
		des_cipher_hex TEXT NOT NULL,
		des_duration_ns BIGINT NOT NULL,
		des_cipher_size INT NOT NULL,
		plaintext_size INT NOT NULL,
		sha256_checksum VARCHAR(64) NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);`

	storedFilesTable := `
	CREATE TABLE IF NOT EXISTS stored_files (
		id VARCHAR(64) PRIMARY KEY,
		user_id VARCHAR(64) NOT NULL,
		category VARCHAR(64) NOT NULL,
		file_name VARCHAR(255) NOT NULL,
		mime_type VARCHAR(128) NOT NULL,
		original_size BIGINT NOT NULL,
		sha256_checksum VARCHAR(64) NOT NULL,
		aes_file_path TEXT NOT NULL,
		aes_duration_ns BIGINT NOT NULL,
		aes_cipher_size BIGINT NOT NULL,
		rc4_file_path TEXT NOT NULL,
		rc4_duration_ns BIGINT NOT NULL,
		rc4_cipher_size BIGINT NOT NULL,
		des_file_path TEXT NOT NULL,
		des_duration_ns BIGINT NOT NULL,
		des_cipher_size BIGINT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`

	queries := []string{usersTable, personalDataTable, storedFilesTable}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("executing query %q: %w", q, err)
		}
	}

	log.Println("Database migrations applied successfully.")
	return nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
