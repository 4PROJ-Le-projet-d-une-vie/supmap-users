package api

import "github.com/go-playground/validator/v10"

type ValidationError struct {
	Message string            `json:"message"`
	Details map[string]string `json:"data"`
}

func (e ValidationError) Error() string {
	return e.Message
}

type CreateUserValidator struct {
	Email    string `json:"email" validate:"required,email"`
	Handle   string `json:"handle" validate:"required,min=3,startsnotwith=@"`
	Password string `json:"password" validate:"required,min=8"`
}

type UpdateUserValidator struct {
	Email    *string `json:"email" validate:"omitempty,email"`
	Handle   *string `json:"handle" validate:"omitempty,min=3,startsnotwith=@"`
	Password *string `json:"password" validate:"omitempty,min=8"`
}

type LoginValidator struct {
	Email    *string `json:"email" validate:"omitempty,email"`
	Handle   *string `json:"handle" validate:"omitempty,min=3,startsnotwith=@"`
	Password string  `json:"password" validate:"required,min=8"`
}

func LoginStructValidation(s validator.StructLevel) {
	login := s.Current().Interface().(LoginValidator)

	if (login.Email == nil && login.Handle == nil) || (login.Email != nil && login.Handle != nil) {
		s.ReportError(login.Email, "Email/Handle", "", "EmailOrHandleExclusive", "")
	}
}
