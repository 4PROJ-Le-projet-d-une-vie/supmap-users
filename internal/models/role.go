package models

import "github.com/uptrace/bun"

type Role struct {
	bun.BaseModel `bun:"table:roles"`

	ID   int64  `bun:"id,pk,autoincrement"`
	Name string `bun:"name,unique,notnull"`
}
