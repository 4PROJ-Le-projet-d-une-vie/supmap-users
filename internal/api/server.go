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

	mux.Handle("GET /user/all", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUsers())))
	mux.Handle("GET /user/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUserById())))
	mux.Handle("GET /user/me", s.AuthMiddleware()(s.GetMe()))

	mux.Handle("POST /register", s.Register())
	mux.Handle("POST /user", s.AuthMiddleware()(s.AdminMiddleware()(s.CreateUser())))

	mux.Handle("PATCH /user/me", s.AuthMiddleware()(s.PatchMe()))
	mux.Handle("PATCH /user/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.PatchUser())))

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
