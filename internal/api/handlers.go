package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/matheodrd/httphelper/handler"
	"net/http"
	"strconv"
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

func (s *Server) GetUserById() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		param := r.PathValue("id")

		id, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			return err
		}

		user, err := s.users.FindByID(r.Context(), id)
		if err != nil {
			return err
		}

		if user == nil {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if err := json.NewEncoder(w).Encode(user); err != nil {
			return err
		}

		return nil
	})
}

func (s *Server) GetMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		user, ok := r.Context().Value("user").(*models.User)
		if !ok {
			s.log.Warn("Unauthenticated request to /user/me")
			w.WriteHeader(http.StatusUnauthorized)

			if err := json.NewEncoder(w).Encode(handler.Response[struct{}]{Message: "unauthenticated"}); err != nil {
				return err
			}
			return nil
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(user); err != nil {
			return err
		}
		return nil
	})
}

func (s *Server) Register() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var body CreateUserValidator
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return err
		}

		validate := validator.New()
		if err := validate.Struct(body); err != nil {
			return buildValidationErrors(w, err)
		}

		toInsertUser := &models.User{
			Email:        body.Email,
			Handle:       "@" + body.Handle,
			HashPassword: &body.Password,
			RoleID:       2,
		}

		if err := s.users.Insert(toInsertUser, r.Context()); err != nil {
			return err
		}

		insertedUser, err := s.users.FindByID(r.Context(), toInsertUser.ID)
		if err != nil {
			return err
		}

		// TODO maybe directly return token to authenticate toInsertUser after register
		if err := json.NewEncoder(w).Encode(insertedUser); err != nil {
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
			return buildValidationErrors(w, err)
		}

		toInsertUser := &models.User{
			Email:        body.Email,
			Handle:       "@" + body.Handle,
			HashPassword: &body.Password,
			RoleID:       1,
		}

		if err := s.users.Insert(toInsertUser, r.Context()); err != nil {
			return err
		}

		insertedUser, err := s.users.FindByID(r.Context(), toInsertUser.ID)
		if err != nil {
			return err
		}

		// TODO directly return user without auto authentication
		if err := json.NewEncoder(w).Encode(insertedUser); err != nil {
			return err
		}

		return nil
	})
}

func (s *Server) PatchMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			s.log.Warn("Unauthenticated request to PATCH /user/me")
			w.WriteHeader(http.StatusUnauthorized)

			if err := json.NewEncoder(w).Encode(handler.Response[struct{}]{Message: "unauthenticated"}); err != nil {
				return err
			}
			return nil
		}

		var body UpdateUserValidator
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return err
		}

		validate := validator.New()
		if err := validate.StructPartial(body); err != nil {
			return buildValidationErrors(w, err)
		}

		toUpdateUser := &models.User{ID: authUser.ID}
		if body.Email != nil {
			toUpdateUser.Email = *body.Email
		}

		if body.Handle != nil {
			toUpdateUser.Handle = *body.Handle
		}

		if body.Password != nil {
			toUpdateUser.HashPassword = body.Password // TODO hash password
		}

		if err := s.users.Update(toUpdateUser, r.Context()); err != nil {
			return err
		}

		updatedUser, err := s.users.FindByID(r.Context(), toUpdateUser.ID)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(updatedUser); err != nil {
			return err
		}

		return nil
	})
}

func (s *Server) PatchUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		param := r.PathValue("id")

		id, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			return err
		}

		existingUser, err := s.users.FindByID(r.Context(), id)
		if err != nil {
			http.Error(w, "failed to retrieve user", http.StatusInternalServerError)
			return nil
		}
		if existingUser == nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return nil
		}

		var body UpdateUserValidator
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return nil
		}

		validate := validator.New()
		if err := validate.Struct(body); err != nil {
			return buildValidationErrors(w, err)
		}

		userToUpdate := &models.User{ID: id}
		if body.Email != nil {
			userToUpdate.Email = *body.Email
		}

		if body.Handle != nil {
			userToUpdate.Handle = *body.Handle
		}

		if body.Password != nil {
			userToUpdate.HashPassword = body.Password // TODO hash password
		}

		if err := s.users.Update(userToUpdate, r.Context()); err != nil {
			http.Error(w, "failed to update user", http.StatusInternalServerError)
			return nil
		}

		updatedUser, err := s.users.FindByID(r.Context(), id)
		if err != nil {
			http.Error(w, "failed to fetch updated user", http.StatusInternalServerError)
			return nil
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(updatedUser); err != nil {
			return err
		}

		return nil
	})
}

func buildValidationErrors(w http.ResponseWriter, original error) error {
	var validationErrors validator.ValidationErrors
	errors.As(original, &validationErrors)
	errs := make(map[string]string)

	for _, fieldErr := range validationErrors {
		errs[fieldErr.Field()] = fmt.Sprintf("failed on '%s'", fieldErr.Tag())
	}

	err := json.NewEncoder(w).Encode(&ValidationError{
		Message: "Validation Error",
		Details: errs,
	})
	if err != nil {
		return fmt.Errorf("failed to write validation errors: %s", err)
	}
	w.WriteHeader(http.StatusBadRequest)

	return nil // Finally return nil to fully controls HTTP error
}
