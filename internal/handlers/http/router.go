package http

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func (h *handler) RegisterRoutes(router *gin.Engine) {
	group := router.Group("/api/auth")

	// Entity:auth
	group.POST("/login", h.Login)
	group.POST("/register", h.Register)
	group.POST("/refresh", h.Refresh)
	group.POST("/forgot-password", h.ForgotPassword)
	group.POST("/verify-reset", h.VerifyResetPassword)
	group.POST("/reset-password", h.ResetPassword)

	group.POST("/oauth/login", h.OAuthLogin)

	// Swagger
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}
