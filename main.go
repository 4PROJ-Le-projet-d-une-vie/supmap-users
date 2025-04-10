package main

import (
	"embed"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"log"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

func main() {
	db, err := goose.OpenDBWithDriver("postgres", "postgres://root:root@localhost:5432/public")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("goose: Failed to close DB: %v", err)
		}
	}()

	goose.SetBaseFS(embedMigrations)

	if err := goose.Up(db, "migrations"); err != nil {
		log.Fatalf("goose: Failed to apply migration: %v", err)
	}

	log.Println("Successfully applied migration")

}
