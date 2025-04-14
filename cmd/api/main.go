package main

import (
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"log"
	"log/slog"
	"os"
	"supmap-users/internal/api"
	"supmap-users/internal/config"
	"supmap-users/migrations"
)

func main() {
	conf, err := config.New()

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	if err := migrations.Migrate("postgres", "postgres://root:root@localhost:5432/public", logger); err != nil {
		logger.Error("migration failed", "err", err)
	}

	conn, err := sql.Open("postgres", "postgres://root:root@localhost:5432/public")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	bunDB := bun.NewDB(conn, pgdialect.New())

	server := api.NewServer(conf, logger, bunDB)
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}
