package api

import (
	httpSwagger "github.com/swaggo/http-swagger"
	"log/slog"
	"net/http"
	_ "supmap-users/docs"
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

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.Handle("/docs/", httpSwagger.WrapHandler)

	mux.Handle("GET /users", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUsers())))
	mux.Handle("GET /users/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUserById())))
	mux.Handle("GET /users/me", s.AuthMiddleware()(s.GetMe()))

	mux.Handle("POST /login", s.Login())
	mux.Handle("POST /register", s.Register())
	mux.Handle("POST /refresh", s.Refresh())
	mux.Handle("POST /logout", s.AuthMiddleware()(s.Logout()))

	mux.Handle("POST /users", s.AuthMiddleware()(s.AdminMiddleware()(s.CreateUser())))
	mux.Handle("PATCH /users/me", s.AuthMiddleware()(s.PatchMe()))
	mux.Handle("PATCH /users/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.PatchUser())))
	mux.Handle("DELETE /users/{id}", s.AuthMiddleware()(s.DeleteUser()))
	mux.Handle("PATCH /users/me/update-password", s.AuthMiddleware()(s.UpdatePassword()))

	mux.Handle("GET /users/me/routes", s.AuthMiddleware()(s.getUserRoutes()))
	mux.Handle("GET /users/me/routes/{routeId}", s.AuthMiddleware()(s.GetUserRoutesById()))
	mux.Handle("POST /users/me/routes", s.AuthMiddleware()(s.CreateUserRoute()))
	mux.Handle("PATCH /users/me/routes/{routeId}", s.AuthMiddleware()(s.PatchUserRoute()))
	mux.Handle("DELETE /users/me/routes/{routeId}", s.AuthMiddleware()(s.DeleteUserRoute()))

	// These routes are not exposed outside the LAN
	//  server network and doesn't require securities
	mux.Handle("GET /internal/users/all", s.GetUsers())
	mux.Handle("GET /internal/users/{id}", s.GetUserById())
	mux.Handle("GET /internal/users/check-auth", s.AuthMiddleware()(s.GetMe()))

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
