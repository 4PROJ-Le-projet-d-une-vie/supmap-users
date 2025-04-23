package services

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"log/slog"
	"supmap-users/internal/config"
	"supmap-users/internal/models"
	"supmap-users/internal/repository"
	"time"
)

type Service struct {
	log    *slog.Logger
	config *config.Config
	users  *repository.Users
}

func NewService(log *slog.Logger, config *config.Config, users *repository.Users) *Service {
	return &Service{
		log:    log,
		config: config,
		users:  users,
	}
}

type AuthError struct {
	Message string
	Code    int
}

func NewAuthError(msg string, code int) error {
	return &AuthError{msg, code}
}

func (e AuthError) Error() string {
	return e.Message
}

func (s *Service) AuthenticateWithCredentials(ctx context.Context, email, handle *string, password string) (*models.User, error) {

	var user *models.User
	var err error
	if email != nil {
		user, err = s.users.FindByEmail(ctx, *email)
	} else if handle != nil {
		user, err = s.users.FindByHandle(ctx, *handle)
	} else {
		return nil, NewAuthError("email or handle is missing", 400)
	}

	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, NewAuthError("wrong credentials", 401)
	}

	if user.HashPassword == nil {
		return nil, NewAuthError("wrong credentials", 401)
	}

	if *user.HashPassword != password {
		return nil, NewAuthError("wrong credentials", 401)
	}

	return user, nil
}

func (s *Service) Authenticate(user *models.User) (*string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": user.ID,
		"role":   user.Role.Name,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
	})

	token, err := claims.SignedString([]byte(s.config.JwtSecret))
	if err != nil {
		return nil, err
	}

	return &token, nil
}
