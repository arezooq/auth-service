package http

import (
	serivces "github.com/arezooq/auth-serivce/internal/services"
	"github.com/gin-gonic/gin"
)

type HandlerAuthInterface interface {
	RegisterRoutes(router *gin.Engine)

	// Entity:auth
	Login(c *gin.Context)

}

type handler struct {
	authServiceInterface serivces.AuthService
}

func InitAuthHandler(authServiceInterface serivces.AuthService) HandlerAuthInterface {
	return &handler{authServiceInterface: authServiceInterface}
}