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

func (t *Tokens) Get(ctx context.Context, user *models.User) (*models.Token, error) {
	var token models.Token
	err := t.bun.NewSelect().
		Model(&token).
		Where("user_id = ?", user.ID).
		Limit(1).
		Scan(ctx)

	if err != nil {
		return nil, err
	}

	return &token, nil
}
