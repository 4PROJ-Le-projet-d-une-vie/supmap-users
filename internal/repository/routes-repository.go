package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/uptrace/bun"
	"supmap-users/internal/models"
)

type Routes struct {
	bun *bun.DB
}

func NewRoutes(db *bun.DB) *Routes {
	return &Routes{db}
}

func (r *Routes) GetAllOfUser(ctx context.Context, user *models.User) ([]models.Route, error) {
	var routes []models.Route
	err := r.bun.NewSelect().
		Model(&routes).
		Where("user_id = ?", user.ID).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return routes, nil
}

func (r *Routes) GetRouteUserById(ctx context.Context, userId, routeId int64) (*models.Route, error) {
	var route models.Route
	err := r.bun.NewSelect().
		Model(&route).
		Where("user_id = ?", userId).
		Where("id = ?", routeId).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &route, err
}

func (r *Routes) InsertRoute(ctx context.Context, route *models.Route) error {
	_, err := r.bun.NewInsert().
		Model(route).
		Returning("id").
		Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (r *Routes) UpdateRoute(ctx context.Context, route *models.Route) error {
	_, err := r.bun.NewUpdate().
		Model(route).
		Where("id = ?", route.ID).
		OmitZero().
		Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (r *Routes) DeleteRoute(ctx context.Context, routeId, userId int64) error {
	_, err := r.bun.NewDelete().
		Model(&models.Route{}).
		Where("id = ?", routeId).
		Where("user_id = ?", userId).
		Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}
