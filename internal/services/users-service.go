package services

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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
	roles  *repository.Roles
	tokens *repository.Tokens
	routes *repository.Routes
}

func NewService(log *slog.Logger, config *config.Config, users *repository.Users, roles *repository.Roles, tokens *repository.Tokens, routes *repository.Routes) *Service {
	return &Service{
		log:    log,
		config: config,
		users:  users,
		roles:  roles,
		tokens: tokens,
		routes: routes,
	}
}

type AuthError struct {
	Message string
	Code    int
}

func (e AuthError) Error() string {
	return e.Message
}

type UpdateError struct {
	Message string
}

func (e UpdateError) Error() string {
	return e.Message
}

type DeleteError struct {
	Message string
}

func (e DeleteError) Error() string {
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

type PartialCreateUser struct {
	Email    string
	Handle   string
	Password string
	RoleID   int64
}

func (s *Service) CreateUser(ctx context.Context, body validations.CreateUserValidator) (*models.User, error) {

	role, err := s.roles.FindUserRole(ctx)
	if err != nil {
		return nil, err
	}

	toInsertUser := &PartialCreateUser{
		Email:    body.Email,
		Handle:   "@" + body.Handle,
		Password: body.Password,
		RoleID:   role.ID,
	}

	user, err := s.doCreateUser(ctx, toInsertUser)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) CreateUserForAdmin(ctx context.Context, body validations.AdminCreateUserValidator) (*models.User, error) {
	role, err := s.roles.FindRole(ctx, body.Role)
	if err != nil {
		return nil, err
	}

	toInsertUser := &PartialCreateUser{
		Email:    body.Email,
		Handle:   "@" + body.Handle,
		Password: body.Password,
		RoleID:   role.ID,
	}

	user, err := s.doCreateUser(ctx, toInsertUser)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) doCreateUser(ctx context.Context, partialUser *PartialCreateUser) (*models.User, error) {

	hashed, err := bcrypt.GenerateFromPassword([]byte(partialUser.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	hashStr := string(hashed)

	toInsertUser := &models.User{
		Email:        partialUser.Email,
		Handle:       partialUser.Handle,
		HashPassword: &hashStr,
		RoleID:       partialUser.RoleID,
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

type PartialPatchUser struct {
	Email    *string
	Handle   *string
	Password *string
	RoleID   *int64
}

func (s *Service) PatchUser(ctx context.Context, id int64, body validations.UpdateUserValidator) (*models.User, error) {
	var handle *string
	if body.Handle != nil {
		h := "@" + *body.Handle
		handle = &h
	}

	partialUser := &PartialPatchUser{
		Email:    body.Email,
		Handle:   handle,
		Password: body.Password,
	}

	user, err := s.doPatchUser(ctx, id, partialUser)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) PatchUserForAdmin(ctx context.Context, id int64, body validations.AdminUpdateUserValidator) (*models.User, error) {

	var handle *string
	if body.Handle != nil {
		h := "@" + *body.Handle
		handle = &h
	}

	var roleId *int64
	if body.Role != nil {
		role, err := s.roles.FindRole(ctx, *body.Role)
		if err != nil {
			return nil, err
		}
		roleId = &role.ID
	}

	partialUser := &PartialPatchUser{
		Email:    body.Email,
		Handle:   handle,
		Password: body.Password,
		RoleID:   roleId,
	}

	user, err := s.doPatchUser(ctx, id, partialUser)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) doPatchUser(ctx context.Context, id int64, partialUser *PartialPatchUser) (*models.User, error) {

	userToPatch := &models.User{
		ID:        id,
		UpdatedAt: time.Now(),
	}

	if partialUser.Email != nil {
		userToPatch.Email = *partialUser.Email
	}

	if partialUser.Handle != nil {
		userToPatch.Handle = *partialUser.Handle
	}

	if partialUser.Password != nil {
		hashed, err := s.hashPassword(*partialUser.Password)
		if err != nil {
			return nil, err
		}
		userToPatch.HashPassword = hashed
	}

	if partialUser.RoleID != nil {
		userToPatch.RoleID = *partialUser.RoleID
	}

	err := s.users.Update(userToPatch, ctx)
	if err != nil {
		s.log.Error("Error occurred while updating user", "details", err)
		return nil, &UpdateError{Message: "Error occurred while updating user"}
	}

	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return user, err
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

type DeleteUser struct {
}

func (s *Service) DeleteUser(ctx context.Context, id int64) error {
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if user == nil {
		return &DeleteError{Message: "User not found"}
	}

	err = s.users.Delete(ctx, id)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) Authenticate(ctx context.Context, user *models.User, ip string) (*string, *string, error) {
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
		IP:        ip,
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

var invalidRefreshTokenError = &AuthError{
	Message: "Invalid token",
	Code:    403,
}

func (s *Service) RefreshToken(ctx context.Context, user *models.User, refreshToken string) (*string, error) {
	err := s.checkAuthUserRefreshToken(ctx, user, refreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
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

func (s *Service) GetUserRoutes(ctx context.Context, user *models.User) ([]models.Route, error) {
	routes, err := s.routes.GetAllOfUser(ctx, user)
	if err != nil {
		return nil, err
	}
	return routes, nil
}

func (s *Service) GetUserRouteById(ctx context.Context, userId, routeId int64) (*models.Route, error) {
	route, err := s.routes.GetRouteUserById(ctx, userId, routeId)
	if err != nil {
		return nil, err
	}

	if route == nil {
		return nil, nil
	}

	return route, nil
}

func (s *Service) CreateRouteForUser(ctx context.Context, user *models.User, route *validations.RouteValidator) (*models.Route, error) {

	routeToInsert := mapRoute(route)
	routeToInsert.UserID = user.ID
	routeToInsert.CreatedAt = time.Now()
	routeToInsert.UpdatedAt = time.Now()

	err := s.routes.InsertRoute(ctx, routeToInsert)
	if err != nil {
		return nil, err
	}

	if &routeToInsert.ID == nil {
		return nil, &AuthError{
			Message: "Cannot retrieve inserted route",
			Code:    400,
		}
	}

	return routeToInsert, nil
}

func (s *Service) PatchUserRoute(ctx context.Context, user *models.User, routeID int64, route *validations.RouteValidator) (*models.Route, error) {
	routeToUpdate := mapRoute(route)
	routeToUpdate.ID = routeID
	routeToUpdate.UserID = user.ID
	routeToUpdate.UpdatedAt = time.Now()

	exists, err := s.routes.GetRouteUserById(ctx, user.ID, routeID)
	if err != nil {
		return nil, err
	}
	if exists == nil {
		return nil, nil
	}

	err = s.routes.UpdateRoute(ctx, routeToUpdate)
	if err != nil {
		return nil, err
	}

	return routeToUpdate, nil
}

func mapRoute(route *validations.RouteValidator) *models.Route {
	points := make([]models.Point, len(route.Route))
	for i, point := range route.Route {
		points[i] = models.Point{
			Latitude:  point.Latitude,
			Longitude: point.Longitude,
		}
	}

	return &models.Route{
		Name:  &route.Name,
		Route: points,
	}
}

func (s *Service) DeleteRoute(ctx context.Context, routeID int64, user *models.User) error {
	err := s.routes.DeleteRoute(ctx, routeID, user.ID)
	if err != nil {
		return err
	}
	return nil
}
