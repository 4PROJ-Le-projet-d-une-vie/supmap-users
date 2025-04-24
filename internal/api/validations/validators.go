package validations

import (
	"github.com/go-playground/validator/v10"
)

type ValidationError struct {
	Message string            `json:"message"`
	Details map[string]string `json:"data"`
}

func (e ValidationError) Error() string {
	return e.Message
}

type CreateUserValidator struct {
	Email    string `json:"email" validate:"required,email"`
	Handle   string `json:"handle" validate:"required,lowercase,min=3,startsnotwith=@"`
	Password string `json:"password" validate:"required,min=8"`
}

func (u CreateUserValidator) Validate() error {
	validate := validator.New()
	if err := validate.Struct(u); err != nil {
		return err
	}
	return nil
}

type AdminCreateUserValidator struct {
	CreateUserValidator
	Role string `json:"role" validate:"required,oneof=ROLE_USER ROLE_ADMIN"`
}

func (u AdminCreateUserValidator) Validate() error {
	validate := validator.New()
	if err := validate.Struct(u); err != nil {
		return err
	}
	return nil
}

type UpdateUserValidator struct {
	Email    *string `json:"email" validate:"omitempty,email"`
	Handle   *string `json:"handle" validate:"omitempty,min=3,startsnotwith=@"`
	Password *string `json:"password" validate:"omitempty,min=8"`
}

func (u UpdateUserValidator) Validate() error {
	validate := validator.New()
	if err := validate.StructPartial(u); err != nil {
		return err
	}
	return nil
}

type LoginValidator struct {
	Email    *string `json:"email" validate:"omitempty,email"`
	Handle   *string `json:"handle" validate:"omitempty,min=3,startsnotwith=@"`
	Password string  `json:"password" validate:"required,min=8"`
}

func (c LoginValidator) Validate() error {
	validate := validator.New()
	validate.RegisterStructValidation(LoginStructValidation, LoginValidator{})
	if err := validate.Struct(c); err != nil {
		return err
	}

	return nil
}

func LoginStructValidation(s validator.StructLevel) {
	login := s.Current().Interface().(LoginValidator)

	if (login.Email == nil && login.Handle == nil) || (login.Email != nil && login.Handle != nil) {
		s.ReportError(login.Email, "Email/Handle", "", "EmailOrHandleExclusive", "")
	}
}
