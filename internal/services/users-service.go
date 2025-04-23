package services

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"supmap-users/internal/api/validations"
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

func (e AuthError) Error() string {
	return e.Message
}

func (s *Service) GetAllUsers(ctx context.Context) ([]models.User, error) {
	users, err := s.users.FindAll(ctx)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (s *Service) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) RegisterUser(ctx context.Context, body validations.CreateUserValidator) (*models.User, error) {

	hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	hashStr := string(hashed)

	toInsertUser := &models.User{
		Email:        body.Email,
		Handle:       "@" + body.Handle,
		HashPassword: &hashStr,
		RoleID:       1,
	}

	// Email check
	exists, err := s.users.FindByEmail(ctx, toInsertUser.Email)
	if err != nil {
		return nil, err
	}

	if exists != nil {
		return nil, &AuthError{
			Message: "User with this email already exists",
			Code:    http.StatusConflict,
		}
	}

	// Handle check
	exists, err = s.users.FindByHandle(ctx, toInsertUser.Handle)
	if err != nil {
		return nil, err
	}

	if exists != nil {
		return nil, &AuthError{
			Message: fmt.Sprintf("User with handle %q already exists", toInsertUser.Handle),
			Code:    http.StatusConflict,
		}
	}

	// Insert new user
	if err := s.users.Insert(toInsertUser, ctx); err != nil {
		return nil, err
	}

	// Retrieve user with auto associated ID by postgres
	if &toInsertUser.ID == nil {
		return nil, &AuthError{
			Message: "Cannot retrieve user's ID",
			Code:    http.StatusInternalServerError,
		}
	}

	user, err := s.users.FindByID(ctx, toInsertUser.ID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

var wrongCredentialsError = &AuthError{
	Message: "Wrong credentials",
	Code:    http.StatusUnauthorized,
}

func (s *Service) Login(ctx context.Context, email, handle *string, password string) (*models.User, error) {

	var user *models.User
	var err error
	if email != nil {
		user, err = s.users.FindByEmail(ctx, *email)
	} else if handle != nil {
		user, err = s.users.FindByHandle(ctx, *handle)
	} else {
		return nil, &AuthError{
			Message: "email or handle is missing",
			Code:    http.StatusBadRequest,
		}
	}

	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, wrongCredentialsError
	}

	if user.HashPassword == nil {
		return nil, wrongCredentialsError
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.HashPassword), []byte(password)); err != nil {
		return nil, wrongCredentialsError
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
