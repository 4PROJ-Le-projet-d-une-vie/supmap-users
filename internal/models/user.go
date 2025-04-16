package models

import (
	"github.com/uptrace/bun"
	"time"
)

type User struct {
	bun.BaseModel `bun:"table:users"`

	ID             int64     `bun:"id,pk,autoincrement" json:"id"`
	Email          string    `bun:"email,unique,notnull" json:"email"`
	Handle         string    `bun:"handle,unique,notnull" json:"handle"`
	HashPassword   *string   `bun:"password_hash" json:"-"`
	AuthProvider   string    `bun:"auth_provider,notnull,default:'local'" json:"auth_provider"`
	ProfilePicture *string   `bun:"profile_picture" json:"profile_picture"`
	RoleID         int64     `bun:"role_id,notnull" json:"-"`
	Role           *Role     `bun:"rel:belongs-to,join:role_id=id" json:"role"`
	CreatedAt      time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt      time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}
