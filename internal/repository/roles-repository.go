package repository

import (
	"context"
	"github.com/uptrace/bun"
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

func (r *Roles) FindAdminRole(ctx context.Context) (*models.Role, error) {
	var admin models.Role
	err := r.bun.NewSelect().
		Model(&admin).
		Where("name = ?", "ROLE_ADMIN").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &admin, nil
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
