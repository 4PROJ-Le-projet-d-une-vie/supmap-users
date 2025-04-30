package api

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/matheodrd/httphelper/handler"
	"net/http"
	"strconv"
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
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
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

		return encode(usersDTO, http.StatusOK, w)
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
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Failure 404 {object} services.ErrorWithCode "Utilisateur non trouvé"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/{id} [get]
func (s *Server) GetUserById() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		id, err := decodeParamAsInt64("id", r)
		if err != nil {
			return err
		}

		user, err := s.service.GetUserByID(r.Context(), id)
		if err != nil {
			return err
		}

		if user == nil {
			return encodeNil(http.StatusNotFound, w)
		}

		return encode(*dto.UserToDTO(user), http.StatusOK, w)
	})
}

// GetMe godoc
// @Summary Récupère les informations de l'utilisateur connecté
// @Description Retourne les informations de l'utilisateur actuellement authentifié.
// @Tags Utilisateurs
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.UserDTO
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/me [get]
func (s *Server) GetMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		user, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		return encode(*dto.UserToDTO(user), http.StatusOK, w)
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
// @Failure 400 {object} services.ErrorWithCode
// @Failure 401 {object} services.ErrorWithCode
// @Failure 500 {object} api.InternalErrorResponse
// @Router /login [post]
func (s *Server) Login() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		body, err := handler.Decode[validations.LoginValidator](r)

		user, err := s.service.Login(r.Context(), body.Email, body.Handle, body.Password)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			}
			return err
		}

		accessToken, refreshToken, err := s.service.Authenticate(r.Context(), user)
		if err != nil {
			return err
		}

		tokenResponse := TokenResponse{
			AccessToken:  *accessToken,
			RefreshToken: *refreshToken,
		}

		return encode(tokenResponse, http.StatusOK, w)
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
			return buildValidationErrors(err, w)
		}

		user, err := s.service.CreateUser(r.Context(), body)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			} else {
				return err
			}
		}

		accessToken, refreshToken, err := s.service.Authenticate(r.Context(), user)
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
		return encode(userWithTokenResponse, http.StatusOK, w)
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
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Failure 403 {object} services.ErrorWithCode "Non autorisé (admin requis)"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user [post]
func (s *Server) CreateUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		body, err := handler.Decode[validations.AdminCreateUserValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		user, err := s.service.CreateUserForAdmin(r.Context(), body)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			}
			return err
		}

		return encode(*dto.UserToDTO(user), http.StatusOK, w)
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
// @Failure 400 {object} services.ErrorWithCode "Erreur de validation ou refresh token invalide"
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Router /refresh [post]
func (s *Server) Refresh() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		body, err := handler.Decode[validations.RefreshValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		accessToken, err := s.service.RefreshToken(r.Context(), authUser, body.Token)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			}
			return err
		}

		tokenResponse := TokenResponse{
			AccessToken: *accessToken,
		}

		return encode(tokenResponse, http.StatusOK, w)
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
// @Failure 400 {object} services.ErrorWithCode "Erreur de validation ou refresh token invalide"
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Router /logout [post]
func (s *Server) Logout() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		body, err := handler.Decode[validations.RefreshValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		err = s.service.Logout(r.Context(), authUser, body.Token)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			}
			return err
		}

		return encodeNil(http.StatusNoContent, w)
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
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Failure 409 {object} services.ErrorWithCode "Conflit (par ex. email ou handle déjà utilisé)"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/me [patch]
func (s *Server) PatchMe() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		body, err := handler.Decode[validations.UpdateUserValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		user, err := s.service.PatchUser(r.Context(), authUser.ID, body)
		if err != nil {
			return err
		}

		accessToken, refreshToken, err := s.service.Authenticate(r.Context(), user)
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
		return encode(userWithTokenResponse, http.StatusOK, w)
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
// @Failure 401 {object} services.ErrorWithCode "Non authentifié"
// @Failure 403 {object} services.ErrorWithCode "Accès interdit (l'utilisateur n'est pas administrateur)"
// @Failure 404 {object} services.ErrorWithCode "Utilisateur non trouvé"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/{id} [patch]
func (s *Server) PatchUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		id, err := decodeParamAsInt64("id", r)
		if err != nil {
			return err
		}

		body, err := handler.Decode[validations.UpdateUserValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		user, err := s.service.PatchUser(r.Context(), id, body)
		if err != nil {
			return err
		}

		return encode(*dto.UserToDTO(user), http.StatusOK, w)
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
// @Failure 401 {object} services.ErrorWithCode "Non authentifié ou non autorisé"
// @Failure 404 {object} services.ErrorWithCode "Utilisateur non trouvé"
// @Failure 500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router /user/{id} [delete]
func (s *Server) DeleteUser() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		id, err := decodeParamAsInt64("id", r)
		if err != nil {
			return err
		}

		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			s.log.Warn("Unauthenticated request to DELETE /user/" + strconv.FormatInt(id, 10))
			return encodeNil(http.StatusUnauthorized, w)
		}

		if authUser.Role.Name != "ROLE_ADMIN" && authUser.ID != id {
			return encodeNil(http.StatusUnauthorized, w)
		}

		if err := s.service.DeleteUser(r.Context(), id); err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			}
			return err
		}

		return encodeNil(http.StatusNoContent, w)
	})
}

// getUserRoutes godoc
// @Summary Get user's routes
// @Description Retrieve all saved routes for the authenticated user
// @Tags Routes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.RouteDTO
// @Failure 401 {object} services.ErrorWithCode
// @Failure 500 {object} api.InternalErrorResponse
// @Router /user/me/routes [get]
func (s *Server) getUserRoutes() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		routes, err := s.service.GetUserRoutes(r.Context(), authUser)
		if err != nil {
			return err
		}

		var routesDTO = make([]dto.RouteDTO, len(routes))
		for i, route := range routes {
			routesDTO[i] = *dto.RouteToDTO(&route)
		}

		return encode(routesDTO, http.StatusOK, w)
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
// @Failure 400 {object} services.ErrorWithCode
// @Failure 401 {object} services.ErrorWithCode
// @Failure 404 "Aucune route trouvée pour l'utilisateur authentifié"
// @Failure 500 {object} api.InternalErrorResponse
// @Router /user/me/routes/{routeId} [get]
func (s *Server) GetUserRoutesById() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		routeId, err := decodeParamAsInt64("routeId", r)
		if err != nil {
			return err
		}

		route, err := s.service.GetUserRouteById(r.Context(), authUser.ID, routeId)
		if err == nil && route == nil {
			return encodeNil(http.StatusNotFound, w)
		}

		return encode(*dto.RouteToDTO(route), http.StatusOK, w)
	})
}

// CreateUserRoute godoc
// @Summary      Créer une nouvelle route
// @Description  Crée une nouvelle route pour l'utilisateur authentifié.
// @Tags         Routes
// @Accept       json
// @Produce      json
// @Security 	 BearerAuth
// @Param        body body validations.RouteValidator true "Données de la route à créer"
// @Success      201 {object} dto.RouteDTO "Route créée avec succès"
// @Failure      400 {object} services.ErrorWithCode "Requête invalide ou erreur de validation"
// @Failure      401 {object} services.ErrorWithCode "Non authentifié"
// @Failure      500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router       /user/me/routes [post]
func (s *Server) CreateUserRoute() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		body, err := handler.Decode[validations.RouteValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		route, err := s.service.CreateRouteForUser(r.Context(), authUser, &body)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encode(ewc, ewc.Code, w)
			}
			return err
		}

		return encode(route, http.StatusCreated, w)
	})
}

// PatchUserRoute godoc
// @Summary      Modifier une route utilisateur
// @Description  Met à jour une route existante appartenant à l'utilisateur authentifié.
// @Tags         Routes
// @Accept       json
// @Produce      json
// @Security 	 BearerAuth
// @Param        routeId path int true "Identifiant de la route"
// @Param        body body validations.RouteValidator true "Nouvelles données de la route"
// @Success      200 {object} dto.RouteDTO "Route mise à jour"
// @Failure      400 {object} services.ErrorWithCode "Requête invalide ou erreur de validation"
// @Failure      401 {object} services.ErrorWithCode "Non authentifié"
// @Failure      404 "Route inexistante"
// @Failure      500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router       /user/me/routes/{routeId} [patch]
func (s *Server) PatchUserRoute() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		routeId, err := decodeParamAsInt64("routeId", r)
		if err != nil {
			return err
		}

		body, err := handler.Decode[validations.RouteValidator](r)
		if err != nil {
			return buildValidationErrors(err, w)
		}

		route, err := s.service.PatchUserRoute(r.Context(), authUser, routeId, &body)
		if err != nil || route == nil {
			if route == nil {
				return encodeNil(http.StatusNotFound, w)
			}
			return err
		}

		fmt.Println(route)
		return encode(*dto.RouteToDTO(route), http.StatusOK, w)
	})
}

// DeleteUserRoute godoc
// @Summary      Supprimer une route utilisateur
// @Description  Supprime une route appartenant à l'utilisateur authentifié.
// @Tags         Routes
// @Accept       json
// @Produce      json
// @Security 	 BearerAuth
// @Param        routeId path int true "Identifiant de la route à supprimer"
// @Success      204 {string} string "Route supprimée avec succès"
// @Failure      401 {object} services.ErrorWithCode "Non authentifié"
// @Failure      500 {object} api.InternalErrorResponse "Erreur interne du serveur"
// @Router       /user/me/routes/{routeId} [delete]
func (s *Server) DeleteUserRoute() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		authUser, ok := r.Context().Value("user").(*models.User)
		if !ok {
			return encodeNil(http.StatusUnauthorized, w)
		}

		routeId, err := decodeParamAsInt64("routeId", r)
		if err != nil {
			return err
		}

		err = s.service.DeleteRoute(r.Context(), routeId, authUser)
		if err != nil {
			if ewc := services.DecodeErrorWithCode(err); ewc != nil {
				return encodeNil(ewc.Code, w)
			}
		}

		return encode(nil, 204, w)
	})
}

func decodeParamAsInt64(param string, r *http.Request) (int64, error) {
	value := r.PathValue(param)
	converted, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	return converted, nil
}

func encodeNil(status int, w http.ResponseWriter) error {
	return encode(nil, status, w)
}

func encode(body any, status int, w http.ResponseWriter) error {
	if body == nil {
		w.WriteHeader(status)
		return nil
	}

	if err := handler.Encode(body, status, w); err != nil {
		return err
	}
	return nil
}

func buildValidationErrors(err error, w http.ResponseWriter) error {
	var ve validator.ValidationErrors
	if !errors.As(err, &ve) {
		return err
	}

	errs := make(map[string]string)

	for _, fieldErr := range ve {
		errs[fieldErr.Field()] = fmt.Sprintf("failed on '%s'", fieldErr.Tag())
	}

	validationErrorResponse := validations.ValidationError{Message: "Validation Error", Details: errs}
	return encode(validationErrorResponse, http.StatusBadRequest, w)
}
