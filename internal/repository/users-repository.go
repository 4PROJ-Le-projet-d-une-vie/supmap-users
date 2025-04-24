package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/uptrace/bun"
	"log/slog"
	"supmap-users/internal/models"
)

type Users struct {
	log *slog.Logger
	bun *bun.DB
}

func NewUsers(db *bun.DB, log *slog.Logger) *Users {
	return &Users{
		log: log,
		bun: db,
	}
}

func (u *Users) FindAll(ctx context.Context) ([]models.User, error) {
	var users []models.User
	err := u.bun.NewSelect().
		Model(&users).
		Relation("Role").
		Order("id DESC").
		Scan(ctx)

	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *Users) FindByID(ctx context.Context, id int64) (*models.User, error) {
	var user = &models.User{
		ID: id,
	}
	err := u.bun.NewSelect().
		Model(user).
		Relation("Role").
		WherePK().
		Scan(ctx)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *Users) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := u.bun.NewSelect().
		Model(&user).
		Relation("Role").
		Where("email = ?", email).
		Scan(ctx)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *Users) FindByHandle(ctx context.Context, handle string) (*models.User, error) {
	var user models.User
	err := u.bun.NewSelect().
		Model(&user).
		Relation("Role").
		Where("handle = ?", handle).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil

}

func (u *Users) Insert(user *models.User, ctx context.Context) error {
	if _, err := u.bun.NewInsert().Model(user).Exec(ctx); err != nil {
		return err
	}
	return nil
}

func (u *Users) Update(user *models.User, ctx context.Context) error {
	_, err := u.bun.NewUpdate().
		Model(user).
		Where("id = ?", user.ID).
		OmitZero().
		Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (u *Users) Delete(ctx context.Context, id int64) error {
	_, err := u.bun.NewDelete().
		Model(&models.User{}).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return err
	}

	user, err := u.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if user != nil {
		return fmt.Errorf("user with id %d not deleted", id)
	}

	return nil
}
