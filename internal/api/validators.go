package api

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
