package dto

import (
	"supmap-users/internal/models"
	"time"
)

type UserDTO struct {
	ID             int64     `json:"id"`
	Email          string    `json:"email"`
	Handle         string    `json:"handle"`
	AuthProvider   string    `json:"auth_provider"`
	ProfilePicture *string   `json:"profile_picture,omitempty"`
	Role           RoleDTO   `json:"role,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func UserToDTO(user *models.User) *UserDTO {
	return &UserDTO{
		ID:             user.ID,
		Email:          user.Email,
		Handle:         user.Handle,
		AuthProvider:   user.AuthProvider,
		ProfilePicture: user.ProfilePicture,
		Role: RoleDTO{
			ID:   user.Role.ID,
			Name: user.Role.Name,
		},
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
