package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/matheodrd/httphelper/handler"
	"net/http"
	"supmap-users/internal/models"
)

func (s *Server) GetUsers() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		users, err := s.users.FindAll(r.Context())

		if err != nil {
			return err
		}

		asJson, err := json.Marshal(users)
		if err != nil {
			return err
		}

		_, err = w.Write(asJson)
		if err != nil {
			return err
		}

		return nil
	})
}

func (s *Server) CreateUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var body CreateUserValidator
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return handler.NewErrWithStatus(400, fmt.Errorf("failed to decode body: %w", err))
		}

		validate := validator.New()
		if err := validate.Struct(body); err != nil {
			var validationErrors validator.ValidationErrors
			errors.As(err, &validationErrors)
			errs := make(map[string]string)

			for _, fieldErr := range validationErrors {
				errs[fieldErr.Field()] = fmt.Sprintf("failed on '%s'", fieldErr.Tag())
			}

			asJson, err := json.Marshal(&ValidationError{
				Message: "Validation Error",
				Details: errs,
			})
			if err != nil {
				return fmt.Errorf("failed to encode validation errors: %s", err)
			}

			w.WriteHeader(http.StatusBadRequest)
			_, err = w.Write(asJson)
			if err != nil {
				return err
			}
			return nil
		}

		user := &models.User{
			Email:        body.Email,
			Handle:       "@" + body.Handle,
			HashPassword: &body.Password,
			RoleID:       1,
		}

		if err := s.users.Insert(user, r.Context()); err != nil {
			return err
		}

		return nil
	})
}
