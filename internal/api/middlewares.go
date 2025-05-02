package api

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matheodrd/httphelper/handler"
	"net/http"
	"strings"
	"supmap-users/internal/models"
)

type AuthError struct {
	Error string `json:"error"`
}

var missingHeader = &AuthError{Error: "Authorization Header is missing"}
var sessionExpired = &AuthError{Error: "session is expired"}
var invalidToken = &AuthError{Error: "invalid token"}
var invalidUser = &AuthError{Error: "invalid user"}

func (s *Server) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				if err := handler.Encode(missingHeader, http.StatusUnauthorized, w); err != nil {
					s.log.Error("Error encoding response", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			userID, err := decodeJWT(token, s.Config.JwtSecret)
			if err != nil {
				if err := handler.Encode(invalidToken, http.StatusUnauthorized, w); err != nil {
					s.log.Error("Error encoding response", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			user, err := s.service.GetUserByID(r.Context(), *userID)
			if err != nil {
				if err := handler.Encode(invalidUser, http.StatusUnauthorized, w); err != nil {
					s.log.Error("Error encoding response", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			if user == nil {
				if err := handler.Encode(invalidUser, http.StatusUnauthorized, w); err != nil {
					s.log.Error("Error encoding response", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			isAuthenticate := s.service.IsAuthenticated(r.Context(), user)
			if !isAuthenticate {
				if err := handler.Encode(sessionExpired, http.StatusUnauthorized, w); err != nil {
					s.log.Error("Error while try to retrieve user", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			if user == nil {
				if err := handler.Encode(invalidToken, http.StatusUnauthorized, w); err != nil {
					s.log.Error("User not found", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

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

func decodeJWT(tokenStr string, secret string) (*int64, error) {
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}

	userId, ok := claims["userId"].(float64)
	if !ok {
		return nil, fmt.Errorf("userId is missing or of wrong type")
	}

	convertedId := int64(userId)
	return &convertedId, nil
}
