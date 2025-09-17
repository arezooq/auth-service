package repositories

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

func InitPostgres() (*sql.DB, error) {
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		return nil, fmt.Errorf("POSTGRES_URL is not set")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	fmt.Println("Postgres connected")
	return db, nil
}
