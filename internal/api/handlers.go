package api

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/matheodrd/httphelper/handler"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"supmap-users/internal/api/validations"
	"supmap-users/internal/models"
	"supmap-users/internal/services"
)

type TokenResponse struct {
	Token string `json:"token"`
}

func (s *Server) GetUsers() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		users, err := s.service.GetAllUsers(r.Context())
		if err != nil {
			return err
		}

		if err := handler.Encode[[]models.User](users, http.StatusOK, w); err != nil {
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

		user, err := s.service.GetUserByID(r.Context(), id)
		if err != nil {
			return err
		}

		if user == nil {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if err := handler.Encode[models.User](*user, http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

func (s *Server) GetMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		user, ok := r.Context().Value("user").(*models.User)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		if err := handler.Encode[models.User](*user, http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}

type AuthErrorResponse struct {
	Error string `json:"error"`
}

func (s *Server) Login() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		body, err := handler.Decode[validations.LoginValidator](r)

		user, err := s.service.Login(r.Context(), body.Email, body.Handle, body.Password)
		if err != nil {
			if authErr := decodeAuthError(err); authErr != nil {
				authErrResponse := AuthErrorResponse{Error: authErr.Message}
				if err := handler.Encode(authErrResponse, authErr.Code, w); err != nil {
					return err
				}
				return nil
			}
			return err
		}

		jwtToken, err := s.service.Authenticate(user)
		if err != nil {
			return err
		}

		tokenResponse := TokenResponse{Token: *jwtToken}
		if err := handler.Encode[TokenResponse](tokenResponse, http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}

type RegisterResponse struct {
	User  *models.User `json:"user"`
	Token *string      `json:"token"`
}

func (s *Server) Register() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		body, err := handler.Decode[validations.CreateUserValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		user, err := s.service.CreateUser(r.Context(), body)
		if err != nil {
			if authError := decodeAuthError(err); authError != nil {
				authErrResponse := AuthErrorResponse{Error: authError.Message}
				if err := handler.Encode(authErrResponse, authError.Code, w); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}

		jwtToken, err := s.service.Authenticate(user)
		if err != nil {
			return err
		}

		registerResponse := RegisterResponse{
			User:  user,
			Token: jwtToken,
		}
		if err := handler.Encode[RegisterResponse](registerResponse, http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

func (s *Server) CreateUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		body, err := handler.Decode[validations.AdminCreateUserValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		user, err := s.service.CreateUserForAdmin(r.Context(), body)
		if err != nil {
			if authError := decodeAuthError(err); authError != nil {
				authErrResponse := AuthErrorResponse{Error: authError.Message}
				if err := handler.Encode(authErrResponse, authError.Code, w); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}

		if err := handler.Encode[models.User](*user, http.StatusOK, w); err != nil {
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
			return nil
		}

		body, err := handler.Decode[validations.UpdateUserValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		toUpdateUser := &models.User{ID: authUser.ID}
		if body.Email != nil {
			toUpdateUser.Email = *body.Email
		}

		if body.Handle != nil {
			toUpdateUser.Handle = *body.Handle
		}

		if body.Password != nil {
			hashed, err := bcrypt.GenerateFromPassword([]byte(*body.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			hashStr := string(hashed)
			toUpdateUser.HashPassword = &hashStr
		}

		if err := s.users.Update(toUpdateUser, r.Context()); err != nil {
			return err
		}

		updatedUser, err := s.users.FindByID(r.Context(), toUpdateUser.ID)
		if err != nil {
			return err
		}

		if err := handler.Encode[models.User](*updatedUser, http.StatusOK, w); err != nil {
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

		body, err := handler.Decode[validations.UpdateUserValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		userToUpdate := &models.User{ID: id}
		if body.Email != nil {
			userToUpdate.Email = *body.Email
		}

		if body.Handle != nil {
			userToUpdate.Handle = *body.Handle
		}

		if body.Password != nil {
			hashed, err := bcrypt.GenerateFromPassword([]byte(*body.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			hashStr := string(hashed)
			userToUpdate.HashPassword = &hashStr
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

		if err := handler.Encode[models.User](*updatedUser, http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

func decodeValidationError(err error) validator.ValidationErrors {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		return ve
	}
	return nil
}

func decodeAuthError(err error) *services.AuthError {
	var ae *services.AuthError
	if errors.As(err, &ae) {
		return ae
	}

	return nil
}

func buildValidationErrors(w http.ResponseWriter, errors validator.ValidationErrors) error {
	errs := make(map[string]string)

	for _, fieldErr := range errors {
		errs[fieldErr.Field()] = fmt.Sprintf("failed on '%s'", fieldErr.Tag())
	}

	validationErrorResponse := validations.ValidationError{Message: "Validation Error", Details: errs}
	err := handler.Encode[validations.ValidationError](validationErrorResponse, http.StatusBadRequest, w)
	if err != nil {
		return err
	}

	return nil // Finally return nil to fully controls HTTP error
}

func (s *Server) DeleteUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		param := r.PathValue("id")

		id, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			return err
		}

		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			s.log.Warn("Unauthenticated request to DELETE /user/" + param)
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		if authUser.Role.Name != "ROLE_ADMIN" && authUser.ID != id {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		if err := s.users.Delete(r.Context(), id); err != nil {
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}
