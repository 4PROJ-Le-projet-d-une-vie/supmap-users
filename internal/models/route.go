package models

import (
	"github.com/uptrace/bun"
	"time"
)

type Point struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lng"`
}

type Route struct {
	bun.BaseModel `bun:"table:routes"`

	ID     int64 `bun:",pk,autoincrement"`
	UserID int64 `bun:"user_id,notnull"`
	User   *User `bun:"rel:belongs-to,join:user_id=id"`

	Name  *string `bun:"name,nullzero"`
	Route []Point `bun:"route,type:jsonb"`

	CreatedAt time.Time `bun:"created_at,default:current_timestamp"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,default:current_timestamp"`
}
