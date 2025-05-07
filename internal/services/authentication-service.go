package services

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"supmap-users/internal/models"
	"time"
)

var wrongCredentialsError = &ErrorWithCode{
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
		return nil, &ErrorWithCode{
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

	if err := s.checkPassword(password, user); err != nil {
		return nil, wrongCredentialsError
	}

	return user, nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*string, error) {
	user, err := s.tokens.GetUserFromRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, invalidRefreshTokenError
	}

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (s *Service) Authenticate(ctx context.Context, user *models.User) (*string, *string, error) {
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, nil, err
	}

	token, err := s.tokens.Get(ctx, user)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}

	if token != nil {
		return accessToken, &token.Token, nil
	}

	refreshToken, err := s.generateRefreshToken(64)
	if err != nil {
		return nil, nil, err
	}

	err = s.tokens.Delete(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	savedToken := &models.Token{
		UserID:    user.ID,
		Token:     *refreshToken,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * 365 * time.Hour),
	}
	err = s.tokens.Insert(ctx, savedToken)
	if err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

func (s *Service) Logout(ctx context.Context, user *models.User, refreshToken string) error {
	err := s.checkAuthUserRefreshToken(ctx, user, refreshToken)
	if err != nil {
		return err
	}

	err = s.tokens.Delete(ctx, user)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) generateAccessToken(user *models.User) (*string, error) {
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

func (s *Service) generateRefreshToken(length int) (*string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(bytes)
	return &token, nil
}

func (s *Service) hashPassword(password string) (*string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	hashStr := string(hashed)
	return &hashStr, nil
}

func (s *Service) checkPassword(password string, user *models.User) error {
	return bcrypt.CompareHashAndPassword([]byte(*user.HashPassword), []byte(password))
}

var invalidRefreshTokenError = &ErrorWithCode{
	Message: "Invalid token",
	Code:    403,
}

func (s *Service) checkAuthUserRefreshToken(ctx context.Context, user *models.User, refreshToken string) error {
	token, err := s.tokens.Get(ctx, user)
	if err != nil {
		return err
	}

	if token == nil {
		return invalidRefreshTokenError
	}

	if token.Token != refreshToken {
		return invalidRefreshTokenError
	}

	return nil
}

func (s *Service) IsAuthenticated(ctx context.Context, user *models.User) bool {
	token, err := s.tokens.Get(ctx, user)
	if err != nil {
		return false
	}

	if token == nil {
		return false
	}

	if token.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}
