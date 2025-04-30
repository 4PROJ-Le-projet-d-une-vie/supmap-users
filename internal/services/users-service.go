package services

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"supmap-users/internal/api/validations"
	"supmap-users/internal/config"
	"supmap-users/internal/helpers"
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

type ErrorWithCode struct {
	Message string `json:"error"`
	Code    int    `json:"-"`
}

func (e ErrorWithCode) Error() string {
	return e.Message
}

func DecodeErrorWithCode(err error) *ErrorWithCode {
	var ewc *ErrorWithCode
	if errors.As(err, &ewc) {
		return ewc
	}
	return nil
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
		return nil, &ErrorWithCode{
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
		return nil, &ErrorWithCode{
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
		return nil, &ErrorWithCode{
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
	Email          *string
	Handle         *string
	ProfilePicture helpers.NullString
	Password       *string
	RoleID         *int64
}

func (s *Service) PatchUser(ctx context.Context, id int64, body validations.UpdateUserValidator) (*models.User, error) {
	var handle *string
	if body.Handle != nil {
		h := "@" + *body.Handle
		handle = &h
	}

	partialUser := &PartialPatchUser{
		Email:          body.Email,
		Handle:         handle,
		ProfilePicture: body.ProfilePicture,
		Password:       body.Password,
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
		Email:          body.Email,
		Handle:         handle,
		ProfilePicture: body.ProfilePicture,
		Password:       body.Password,
		RoleID:         roleId,
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

	if partialUser.ProfilePicture.Set {
		if partialUser.ProfilePicture.Value != nil && *partialUser.ProfilePicture.Value != "" {
			userToPatch.ProfilePicture = partialUser.ProfilePicture.Value
		} else {
			userToPatch.ProfilePicture = nil
		}

		if err := s.users.UpdateProfilePicture(userToPatch, ctx); err != nil {
			return nil, err
		}
	}

	err := s.users.Update(userToPatch, ctx)
	if err != nil {
		return nil, err
	}

	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return user, err
}

type DeleteUser struct {
}

func (s *Service) DeleteUser(ctx context.Context, id int64) error {
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if user == nil {
		return &ErrorWithCode{
			Message: "User not found",
			Code:    http.StatusNotFound,
		}
	}

	err = s.users.Delete(ctx, id)
	if err != nil {
		return err
	}
	return nil
}
