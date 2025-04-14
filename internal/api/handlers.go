package api

import (
	"github.com/matheodrd/httphelper/handler"
	"net/http"
)

func (s *Server) GetUsers() http.HandlerFunc {
	return handler.Handler(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})
}
