package services

import (
	"context"
	"net/http"
	"supmap-users/internal/api/validations"
	"supmap-users/internal/models"
	"time"
)

func (s *Service) GetUserRoutes(ctx context.Context, user *models.User) ([]models.Route, error) {
	routes, err := s.routes.GetAllOfUser(ctx, user)
	if err != nil {
		return nil, err
	}
	return routes, nil
}

func (s *Service) GetUserRouteById(ctx context.Context, userId, routeId int64) (*models.Route, error) {
	route, err := s.routes.GetRouteUserById(ctx, userId, routeId)
	if err != nil {
		return nil, err
	}

	if route == nil {
		return nil, nil
	}

	return route, nil
}

func (s *Service) CreateRouteForUser(ctx context.Context, user *models.User, route *validations.RouteValidator) (*models.Route, error) {

	routeToInsert := mapRoute(route)
	routeToInsert.UserID = user.ID
	routeToInsert.CreatedAt = time.Now()
	routeToInsert.UpdatedAt = time.Now()

	err := s.routes.InsertRoute(ctx, routeToInsert)
	if err != nil {
		return nil, err
	}

	if &routeToInsert.ID == nil {
		return nil, &ErrorWithCode{
			Message: "Cannot retrieve inserted route",
			Code:    http.StatusBadRequest,
		}
	}

	return routeToInsert, nil
}

func (s *Service) PatchUserRoute(ctx context.Context, user *models.User, routeID int64, route *validations.RouteValidator) (*models.Route, error) {
	routeToUpdate := mapRoute(route)
	routeToUpdate.ID = routeID
	routeToUpdate.UserID = user.ID
	routeToUpdate.UpdatedAt = time.Now()

	exists, err := s.routes.GetRouteUserById(ctx, user.ID, routeID)
	if err != nil {
		return nil, err
	}
	if exists == nil {
		return nil, nil
	}

	err = s.routes.UpdateRoute(ctx, routeToUpdate)
	if err != nil {
		return nil, err
	}

	return routeToUpdate, nil
}

func (s *Service) DeleteRoute(ctx context.Context, routeID int64, user *models.User) error {
	exists, err := s.routes.GetRouteUserById(ctx, user.ID, routeID)
	if err != nil {
		return err
	}

	if exists == nil {
		return &ErrorWithCode{
			Message: "Route does not exist",
			Code:    404,
		}
	}

	err = s.routes.DeleteRoute(ctx, routeID, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func mapRoute(route *validations.RouteValidator) *models.Route {
	points := make([]models.Point, len(route.Route))
	for i, point := range route.Route {
		points[i] = models.Point{
			Latitude:  point.Latitude,
			Longitude: point.Longitude,
		}
	}

	return &models.Route{
		Name:  &route.Name,
		Route: points,
	}
}
