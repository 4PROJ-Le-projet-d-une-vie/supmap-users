package repository

import (
	"context"
	"github.com/uptrace/bun"
	"strings"
	"supmap-users/internal/models"
)

type Roles struct {
	bun *bun.DB
}

func NewRoles(db *bun.DB) *Roles {
	return &Roles{
		bun: db,
	}
}

func (r *Roles) FindUserRole(ctx context.Context) (*models.Role, error) {
	var user models.Role
	err := r.bun.NewSelect().
		Model(&user).
		Where("name = ?", "ROLE_USER").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *Roles) FindRole(ctx context.Context, role string) (*models.Role, error) {
	var admin models.Role
	err := r.bun.NewSelect().
		Model(&admin).
		Where("name = ?", strings.ToUpper(role)).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &admin, nil
}
