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
	"supmap-users/internal/models/dto"
	"supmap-users/internal/services"
)

type InternalErrorResponse struct {
	Message string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// GetUsers godoc
// @Summary Récupère tous les utilisateurs
// @Description Retourne une liste complète de tous les utilisateurs enregistrés. Nécessite une authentification.
// @Tags Utilisateurs
// @Security BearerAuth
// @Produce json
// @Success 200 {array} dto.UserDTO
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/all [get]
func (s *Server) GetUsers() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		users, err := s.service.GetAllUsers(r.Context())
		if err != nil {
			return err
		}

		var usersDTO = make([]dto.UserDTO, len(users))
		for i, user := range users {
			usersDTO[i] = *dto.UserToDTO(&user)
		}

		if err := handler.Encode[[]dto.UserDTO](usersDTO, http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

// GetUserById godoc
// @Summary Récupère un utilisateur par son ID
// @Description Retourne un utilisateur correspondant à l'ID donné. Nécessite une authentification.
// @Tags Utilisateurs
// @Security BearerAuth
// @Produce json
// @Param id path int true "ID de l'utilisateur"
// @Success 200 {object} dto.UserDTO
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Failure 404 {object} api.ErrorResponse "Utilisateur non trouvé"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/{id} [get]
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

		if err := handler.Encode[dto.UserDTO](*dto.UserToDTO(user), http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

// GetMe godoc
// @Summary Récupère les informations de l'utilisateur connecté
// @Description Retourne les informations de l'utilisateur actuellement authentifié.
// @Tags Utilisateurs
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.UserDTO
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/me [get]
func (s *Server) GetMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		user, ok := r.Context().Value("user").(*models.User)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		if err := handler.Encode[dto.UserDTO](*dto.UserToDTO(user), http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}

// Login godoc
// @Summary Authentification d'un utilisateur
// @Description Authentifie un utilisateur via son email ou handle et son mot de passe, et retourne un access token ainsi qu’un refresh token.
// @Tags Authentification
// @Accept json
// @Produce json
// @Param data body validations.LoginValidator true "Données de connexion"
// @Success 200 {object} api.TokenResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.InternalErrorResponse
// @Router /login [post]
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
	User  *dto.UserDTO   `json:"user"`
	Token *TokenResponse `json:"tokens"`
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with email, handle, and password. Returns the created user and JWT tokens.
// @Tags Authentification
// @Accept json
// @Produce json
// @Param request body validations.CreateUserValidator true "User registration payload"
// @Success 200 {object} UserWithTokenResponse
// @Failure 400 {object} ErrorResponse "Validation error or malformed request"
// @Failure 409 {object} ErrorResponse "User already exists or conflict"
// @Failure 500 {object} api.InternalErrorResponse "Internal server error"
// @Router /register [post]
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
			User: dto.UserToDTO(user),
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

// CreateUser godoc
// @Summary Crée un nouvel utilisateur (admin uniquement)
// @Description Permet à un administrateur de créer un utilisateur avec un rôle personnalisé.
// @Tags Utilisateurs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param payload body validations.AdminCreateUserValidator true "Données du nouvel utilisateur"
// @Success 200 {object} dto.UserDTO
// @Failure 400 {object} validations.ValidationError "Erreur de validation"
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Failure 403 {object} api.ErrorResponse "Non autorisé (admin requis)"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user [post]
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

		if err := handler.Encode[dto.UserDTO](*dto.UserToDTO(user), http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

// Refresh godoc
// @Summary Rafraîchit le token d'accès de l'utilisateur
// @Description Permet d'obtenir un nouveau token d'accès à partir d'un refresh token valide.
// @Tags Authentification
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param data body validations.RefreshValidator true "Refresh Token"
// @Success 200 {object} api.TokenResponse
// @Failure 400 {object} api.ErrorResponse "Erreur de validation ou refresh token invalide"
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Router /refresh [post]
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

// Logout godoc
// @Summary Déconnecte l'utilisateur
// @Description Invalide le refresh token de l'utilisateur, ce qui le déconnecte complètement.
// @Tags Authentification
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param data body validations.RefreshValidator true "Refresh Token"
// @Success 204 "Déconnexion réussie"
// @Failure 400 {object} api.ErrorResponse "Erreur de validation ou refresh token invalide"
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Router /logout [post]
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

		w.WriteHeader(http.StatusNoContent)
		return nil
	})
}

// PatchMe godoc
// @Summary Met à jour les informations de l'utilisateur connecté
// @Description Permet à l'utilisateur actuellement authentifié de mettre à jour ses informations personnelles.
// @Tags Utilisateurs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param payload body validations.UpdateUserValidator true "Données à mettre à jour"
// @Success 200 {object} api.UserWithTokenResponse
// @Failure 400 {object} validations.ValidationError "Erreur de validation"
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Failure 409 {object} api.ErrorResponse "Conflit (par ex. email ou handle déjà utilisé)"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/me [patch]
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
			User: dto.UserToDTO(user),
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

// PatchUser godoc
// @Summary Mise à jour d'un utilisateur par un administrateur
// @Description Permet à un administrateur de mettre à jour les informations d'un utilisateur spécifié par ID.
// @Tags Utilisateurs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "ID de l'utilisateur à mettre à jour"
// @Param payload body validations.UpdateUserValidator true "Données à mettre à jour"
// @Success 200 {object} dto.UserDTO
// @Failure 400 {object} validations.ValidationError "Erreur de validation"
// @Failure 401 {object} api.ErrorResponse "Non authentifié"
// @Failure 403 {object} api.ErrorResponse "Accès interdit (l'utilisateur n'est pas administrateur)"
// @Failure 404 {object} api.ErrorResponse "Utilisateur non trouvé"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/{id} [patch]
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

		if err := handler.Encode[dto.UserDTO](*dto.UserToDTO(user), http.StatusOK, w); err != nil {
			return err
		}

		return nil
	})
}

// DeleteUser godoc
// @Summary Suppression d'un utilisateur
// @Description Permet de supprimer un utilisateur par son ID. L'utilisateur peut supprimer son propre compte ou un administrateur peut supprimer n'importe quel compte.
// @Tags Utilisateurs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "ID de l'utilisateur à supprimer"
// @Success 204 "Utilisateur supprimé avec succès"
// @Failure 400 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Failure 401 {object} api.ErrorResponse "Non authentifié ou non autorisé"
// @Failure 404 {object} api.ErrorResponse "Utilisateur non trouvé"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/{id} [delete]
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

// getUserRoutes godoc
// @Summary Get user's routes
// @Description Retrieve all saved routes for the authenticated user
// @Tags Routes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.RouteDTO
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /user/me/routes [get]
func (s *Server) getUserRoutes() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}
		routes, err := s.service.GetUserRoutes(r.Context(), authUser)
		if err != nil {
			return err
		}

		var routesDTO = make([]dto.RouteDTO, len(routes))
		for i, route := range routes {
			routesDTO[i] = *dto.RouteToDTO(&route)
		}
		if err := handler.Encode(routesDTO, http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}

// GetUserRoutesById godoc
// @Summary Get a user's route by ID
// @Description Retrieve a specific route saved by the authenticated user using the route ID
// @Tags Routes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param routeId path int true "Route ID"
// @Success 200 {object} dto.RouteDTO
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 404 "Aucune route trouvée pour l'utilisateur authentifié"
// @Failure 500 {object} api.ErrorResponse
// @Router /user/me/routes/{routeId} [get]
func (s *Server) GetUserRoutesById() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}

		param := r.PathValue("routeId")
		routeId, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			return err
		}

		route, err := s.service.GetUserRouteById(r.Context(), authUser.ID, routeId)
		if err == nil && route == nil {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		if err := handler.Encode(*dto.RouteToDTO(route), http.StatusOK, w); err != nil {
			return err
		}
		return nil
	})
}
