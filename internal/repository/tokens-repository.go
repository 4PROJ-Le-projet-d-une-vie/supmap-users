package repository

import (
	"context"
	"github.com/uptrace/bun"
	"supmap-users/internal/models"
)

type Tokens struct {
	bun *bun.DB
}

func NewTokens(db *bun.DB) *Tokens {
	return &Tokens{db}
}

func (t *Tokens) Insert(ctx context.Context, token *models.Token) error {
	if _, err := t.bun.NewInsert().Model(token).Exec(ctx); err != nil {
		return err
	}
	return nil
}

func (t *Tokens) Delete(ctx context.Context, user *models.User) error {
	_, err := t.bun.NewDelete().
		Model((*models.Token)(nil)).
		Where("user_id = ?", user.ID).
		Exec(ctx)

	return err
}
