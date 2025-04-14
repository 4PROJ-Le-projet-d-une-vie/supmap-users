package api

import (
	"github.com/uptrace/bun"
	"log/slog"
	"net/http"
	"supmap-users/internal/config"
)

type Server struct {
	Config *config.Config
	log    *slog.Logger
	bun    *bun.DB
}

func NewServer(config *config.Config, log *slog.Logger, db *bun.DB) *Server {
	return &Server{
		Config: config,
		log:    log,
		bun:    db,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /route", s.GetUsers())

	server := &http.Server{
		Addr:    s.Config.PORT,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
