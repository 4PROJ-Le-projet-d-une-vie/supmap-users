package models

import "github.com/uptrace/bun"

type Role struct {
	bun.BaseModel `bun:"table:roles"`

	ID   int64  `bun:"id,pk,autoincrement" json:"id"`
	Name string `bun:"name,unique,notnull" json:"name"`
}
