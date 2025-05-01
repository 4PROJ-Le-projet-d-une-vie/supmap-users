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

	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	mux.Handle("GET /user/all", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUsers())))
	mux.Handle("GET /user/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.GetUserById())))
	mux.Handle("GET /user/me", s.AuthMiddleware()(s.GetMe()))

	mux.Handle("POST /login", s.Login())
	mux.Handle("POST /register", s.Register())
	mux.Handle("POST /refresh", s.AuthMiddleware()(s.Refresh()))
	mux.Handle("POST /logout", s.AuthMiddleware()(s.Logout()))

	mux.Handle("POST /user", s.AuthMiddleware()(s.AdminMiddleware()(s.CreateUser())))
	mux.Handle("PATCH /user/me", s.AuthMiddleware()(s.PatchMe()))
	mux.Handle("PATCH /user/{id}", s.AuthMiddleware()(s.AdminMiddleware()(s.PatchUser())))
	mux.Handle("DELETE /user/{id}", s.AuthMiddleware()(s.DeleteUser()))
	mux.Handle("PATCH /user/me/update-password", s.AuthMiddleware()(s.UpdatePassword()))

	mux.Handle("GET /user/me/routes", s.AuthMiddleware()(s.getUserRoutes()))
	mux.Handle("GET /user/me/routes/{routeId}", s.AuthMiddleware()(s.GetUserRoutesById()))
	mux.Handle("POST /user/me/routes", s.AuthMiddleware()(s.CreateUserRoute()))
	mux.Handle("PATCH /user/me/routes/{routeId}", s.AuthMiddleware()(s.PatchUserRoute()))
	mux.Handle("DELETE /user/me/routes/{routeId}", s.AuthMiddleware()(s.DeleteUserRoute()))

	// These routes are not exposed outside the LAN
	//  server network and doesn't require securities
	mux.Handle("GET /internal/user/all", s.GetUsers())
	mux.Handle("GET /internal/user/{id}", s.GetUserById())

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
