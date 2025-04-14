package migrations

import (
	"embed"
	"github.com/pressly/goose/v3"
	"log/slog"
)

//go:embed changelog/*.sql
var changelog embed.FS

func Migrate(driver string, url string, log *slog.Logger) (err error) {
	db, err := goose.OpenDBWithDriver(driver, url)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			if err == nil {
				err = cerr
			} else {
				log.Info("erreur à la fermeture de la DB : %v", cerr)
			}
		}
	}()

	goose.SetBaseFS(changelog)

	if err := goose.Up(db, "changelog"); err != nil {
		return err
	}

	log.Info("Successfully applied migration")
	return nil
}
