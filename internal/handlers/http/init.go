package http

import (
	"auth-service/internal/services"
	"github.com/gin-gonic/gin"
)

type HandlerAuthInterface interface {
	RegisterRoutes(router *gin.Engine)

	// Entity:auth
	Login(c *gin.Context)
	Register(c *gin.Context)
	Refresh(c *gin.Context)
	ForgotPassword(c *gin.Context)
	VerifyResetPassword(c *gin.Context)
	ResetPassword(c *gin.Context)

}

type handler struct {
	authService services.AuthService
}

func InitAuthHandler(authService services.AuthService) HandlerAuthInterface {
	return &handler{authService: authService}
}