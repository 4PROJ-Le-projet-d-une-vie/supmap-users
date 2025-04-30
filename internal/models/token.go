package models

import (
	"github.com/uptrace/bun"
	"time"
)

type Token struct {
	bun.BaseModel `bun:"table:refresh_tokens"`

	UserID    int64     `bun:"user_id,pk"`
	User      *User     `bun:"rel:belongs-to,join:user_id=id"`
	Token     string    `bun:"token,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
}
