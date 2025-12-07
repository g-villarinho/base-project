package sqlite

import (
	"database/sql"
	"fmt"

	"github.com/g-villarinho/base-project/config"
	_ "github.com/mattn/go-sqlite3"
	migrate "github.com/rubenv/sql-migrate"
)

func NewDbConnection(config *config.Config) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", config.SqlLite.DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxIdleConns(config.SqlLite.MaxIdle)
	db.SetMaxOpenConns(config.SqlLite.MaxConn)
	db.SetConnMaxLifetime(config.SqlLite.MaxLifeTime)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return db, nil
}

func runMigrations(db *sql.DB) error {
	migrations := &migrate.FileMigrationSource{
		Dir: "internal/database/migrations",
	}

	n, err := migrate.Exec(db, "sqlite3", migrations, migrate.Up)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	if n > 0 {
		fmt.Printf("Applied %d migrations\n", n)
	}

	return nil
}
