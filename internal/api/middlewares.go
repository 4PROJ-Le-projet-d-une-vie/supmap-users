package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"supmap-users/internal/models"
)

func (s *Server) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing auth header", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			userID, err := decodeJWT(token)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			user, err := s.users.FindByID(r.Context(), userID)
			if err != nil {
				http.Error(w, "Invalid user", http.StatusUnauthorized)
				return
			}

			s.log.Debug("user: %+v\n", user) // TODO remove debug
			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *Server) AdminMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value("user").(*models.User)
			if !ok {
				s.log.Warn("unauthenticated user tried to access admin route")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if user.Role == nil || user.Role.Name != "ROLE_ADMIN" {
				s.log.Warn("Non admin user tried to access admin route")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func decodeJWT(token string) (int64, error) {
	// TODO decode token here
	fmt.Println(token)
	return 1, nil
}
