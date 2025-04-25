package api

import (
	"log/slog"
	"net/http"
	"supmap-users/internal/config"
	"supmap-users/internal/services"
)

type Server struct {
	Config  *config.Config
	log     *slog.Logger
	service *services.Service
}

func NewServer(config *config.Config, log *slog.Logger, service *services.Service) *Server {
	return &Server{
		Config:  config,
		log:     log,
		service: service,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.Handle("GET /user/all", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUsers())))
	mux.Handle("GET /user/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUserById())))
	mux.Handle("GET /user/me", s.AuthMiddleware()(s.GetMe()))

	mux.Handle("POST /login", s.Login())
	mux.Handle("POST /register", s.Register())
	mux.Handle("POST /refresh", s.AuthMiddleware()(s.Refresh()))
	mux.Handle("POST /user", s.AuthMiddleware()(s.AdminMiddleware()(s.CreateUser())))
	mux.Handle("POST /logout", s.AuthMiddleware()(s.Logout()))

	mux.Handle("PATCH /user/me", s.AuthMiddleware()(s.PatchMe()))
	mux.Handle("PATCH /user/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.PatchUser())))

	mux.Handle("DELETE /user/{id}", s.AuthMiddleware()(s.DeleteUser()))

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
