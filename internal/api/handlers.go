package api

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/matheodrd/httphelper/handler"
	"net"
	"net/http"
	"strconv"
	"strings"
	"supmap-users/internal/api/validations"
	"supmap-users/internal/models"
	"supmap-users/internal/services"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
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

func (s *Server) Login() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		body, err := handler.Decode[validations.LoginValidator](r)

		user, err := s.service.Login(r.Context(), body.Email, body.Handle, body.Password)
		if err != nil {
			if authErr := decodeAuthError(err); authErr != nil {
				authErrResponse := ErrorResponse{Error: authErr.Message}
				if err := handler.Encode(authErrResponse, authErr.Code, w); err != nil {
					return err
				}
				return nil
			}
			return err
		}

		accessToken, refreshToken, err := s.service.Authenticate(r.Context(), user, getIP(r))
		if err != nil {
			return err
		}

		tokenResponse := TokenResponse{
			AccessToken:  *accessToken,
			RefreshToken: *refreshToken,
		}
		if err := handler.Encode[TokenResponse](tokenResponse, http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}

type UserWithTokenResponse struct {
	User  *models.User   `json:"user"`
	Token *TokenResponse `json:"tokens"`
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
				authErrResponse := ErrorResponse{Error: authError.Message}
				if err := handler.Encode(authErrResponse, authError.Code, w); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}

		accessToken, refreshToken, err := s.service.Authenticate(r.Context(), user, getIP(r))
		if err != nil {
			return err
		}

		userWithTokenResponse := UserWithTokenResponse{
			User: user,
			Token: &TokenResponse{
				AccessToken:  *accessToken,
				RefreshToken: *refreshToken,
			},
		}
		if err := handler.Encode[UserWithTokenResponse](userWithTokenResponse, http.StatusOK, w); err != nil {
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
				authErrResponse := ErrorResponse{Error: authError.Message}
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

func (s *Server) Refresh() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		body, err := handler.Decode[validations.RefreshValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		accessToken, err := s.service.RefreshToken(r.Context(), authUser, body.Token)
		if err != nil {
			if authError := decodeAuthError(err); authError != nil {
				authErrResponse := ErrorResponse{Error: authError.Message}
				if err := handler.Encode(authErrResponse, authError.Code, w); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}

		tokenResponse := TokenResponse{
			AccessToken: *accessToken,
		}
		if err := handler.Encode[TokenResponse](tokenResponse, http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}

func (s *Server) Logout() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		body, err := handler.Decode[validations.RefreshValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		err = s.service.Logout(r.Context(), authUser, body.Token)
		if err != nil {
			if authError := decodeAuthError(err); authError != nil {
				authErrResponse := ErrorResponse{Error: authError.Message}
				if err := handler.Encode(authErrResponse, authError.Code, w); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}

		return nil
	})
}

func (s *Server) PatchMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
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

		user, err := s.service.PatchUser(r.Context(), authUser.ID, body)
		if err != nil {
			if updateErr := decodeUpdateError(err); updateErr != nil {

				updateErrResponse := ErrorResponse{
					Error: updateErr.Message,
				}
				if err := handler.Encode(updateErrResponse, http.StatusConflict, w); err != nil {
					return err
				}
				return nil
			}
			return err
		}

		accessToken, refreshToken, err := s.service.Authenticate(r.Context(), user, getIP(r))
		if err != nil {
			return err
		}

		userWithTokenResponse := UserWithTokenResponse{
			User: user,
			Token: &TokenResponse{
				AccessToken:  *accessToken,
				RefreshToken: *refreshToken,
			},
		}
		if err := handler.Encode[UserWithTokenResponse](userWithTokenResponse, http.StatusOK, w); err != nil {
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

		body, err := handler.Decode[validations.UpdateUserValidator](r)
		if err != nil {
			if validationErrors := decodeValidationError(err); validationErrors != nil {
				return buildValidationErrors(w, validationErrors)
			}
			return err
		}

		user, err := s.service.PatchUser(r.Context(), id, body)
		if err != nil {
			return err
		}

		if err := handler.Encode[models.User](*user, http.StatusOK, w); err != nil {
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

func decodeUpdateError(err error) *services.UpdateError {
	var ue *services.UpdateError
	if errors.As(err, &ue) {
		return ue
	}
	return nil
}

func decodeDeleteError(err error) *services.DeleteError {
	var de *services.DeleteError
	if errors.As(err, &de) {
		return de
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

		if err := s.service.DeleteUser(r.Context(), id); err != nil {
			if deleteErr := decodeDeleteError(err); deleteErr != nil {
				w.WriteHeader(http.StatusNotFound)

				deleteErrResponse := ErrorResponse{Error: deleteErr.Error()}
				if err := handler.Encode(deleteErrResponse, http.StatusInternalServerError, w); err != nil {

				}

				return nil
			}
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		parts := strings.Split(ip, ",")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
