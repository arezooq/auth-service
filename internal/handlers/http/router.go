package http

import "github.com/gin-gonic/gin"

func (h *handler) RegisterRoutes(router *gin.Engine) {
	group := router.Group("/api/auth")

	// Entity:auth
	group.POST("/login", h.Login)
	group.POST("/register", h.Register)
	group.POST("/refresh", h.Refresh)
	group.POST("/forgot-password", h.ForgotPassword)
	group.POST("/verify-reset", h.VerifyResetPassword)
	group.POST("/reset-password", h.ResetPassword)
}
