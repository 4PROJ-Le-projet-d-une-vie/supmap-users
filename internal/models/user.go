package models

import (
	"github.com/uptrace/bun"
	"time"
)

type User struct {
	bun.BaseModel `bun:"table:users"`

	ID             int64     `bun:"id,pk,autoincrement"`
	Email          string    `bun:"email,unique,notnull"`
	Handle         string    `bun:"handle,unique,notnull"`
	HashPassword   *string   `bun:"password_hash"`
	AuthProvider   string    `bun:"auth_provider,notnull,default:'local'"`
	ProfilePicture *string   `bun:"profile_picture"`
	RoleID         int64     `bun:"role_id,notnull"`
	Role           *Role     `bun:"rel:belongs-to,join:role_id=id"`
	CreatedAt      time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt      time.Time `bun:"updated_at,notnull,default:current_timestamp"`
}
