package dto

import (
	"supmap-users/internal/models"
	"time"
)

type RouteDTO struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Route     []models.Point `json:"route"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func RouteToDTO(route *models.Route) *RouteDTO {
	return &RouteDTO{
		ID:        route.ID,
		Name:      *route.Name,
		Route:     route.Route,
		CreatedAt: route.CreatedAt,
		UpdatedAt: route.UpdatedAt,
	}
}
