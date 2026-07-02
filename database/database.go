package database

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect() *pgxpool.Pool {
	connStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		slog.Error("unable to create connection pool", "error", err)
		os.Exit(1)
	}

	if err := pool.Ping(context.Background()); err != nil {
		slog.Error("unable to ping database", "error", err)
		os.Exit(1)
	}

	slog.Info("connected to database")
	return pool
}
