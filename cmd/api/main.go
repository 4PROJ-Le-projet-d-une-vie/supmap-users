package main

import (
	"database/sql"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/extra/bundebug"
	"log"
	"log/slog"
	"os"
	"supmap-users/internal/api"
	"supmap-users/internal/config"
	"supmap-users/internal/repository"
	"supmap-users/internal/services"
	"supmap-users/migrations"
)

// @title SupMap Users API
// @version 1.0
// @description Cette API permet de gérer les utilisateurs de SupMap.
// @termsOfService http://example.com/terms/

// @contact.name Ewen
// @contact.email ewen@example.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	conf, err := config.New()

	// Configure logger
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	// Run database migrations
	if err := migrations.Migrate("pgx", "postgres://root:root@localhost:5432/public", logger); err != nil {
		logger.Error("migration failed", "err", err)
	}

	// Open SQL connection
	conn, err := sql.Open("pgx", "postgres://root:root@localhost:5432/public")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	// Create Bun client
	bunDB := bun.NewDB(conn, pgdialect.New())
	if conf.ENV == "development" {
		bunDB.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
	}

	if err := bunDB.Ping(); err != nil {
		log.Fatal(fmt.Errorf("failed to connect to database: %w", err))
	}

	// Create users repository
	users := repository.NewUsers(bunDB, logger)
	roles := repository.NewRoles(bunDB)
	tokens := repository.NewTokens(bunDB)

	// Create users service
	service := services.NewService(logger, conf, users, roles, tokens)

	// Create the HTTP server
	server := api.NewServer(conf, logger, service)
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}
