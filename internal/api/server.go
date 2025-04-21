package api

import (
	"log/slog"
	"net/http"
	"supmap-users/internal/config"
	"supmap-users/internal/repository"
)

type Server struct {
	Config *config.Config
	log    *slog.Logger
	users  *repository.Users
}

func NewServer(config *config.Config, log *slog.Logger, users *repository.Users) *Server {
	return &Server{
		Config: config,
		log:    log,
		users:  users,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /user/all", s.GetUsers())
	mux.HandleFunc("GET /user/{id}", s.GetUserById())
	mux.Handle("GET /user/me", s.AuthMiddleware()(s.GetMe()))
	mux.HandleFunc("POST /user", s.CreateUser())

	server := &http.Server{
		Addr:    ":" + s.Config.PORT,
		Handler: mux,
	}

	s.log.Info("Starting server on port: " + server.Addr)
	if err := server.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
