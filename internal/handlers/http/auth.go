package http

import (
	"net/http"

	"auth-service/internal/constant"
	"auth-service/internal/models"
	"github.com/arezooq/open-utils/errors"
	"github.com/gin-gonic/gin"
)

//	Login
func (h *handler) Login(c *gin.Context) {
	var req constant.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	reqID := c.GetString("reqID")

	resp, err := h.authService.LoginUser(req.Email, req.Password, reqID)
	if err != nil {
		switch err {
		case errors.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		case errors.ErrUnauthorized:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Register
func (h *handler) Register(c *gin.Context) {
	var req models.User
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	reqID := c.GetString("reqID")
	user, err := h.authService.RegisterUser(&req, reqID)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, user)
}

// Refresh
func (h *handler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	reqID := c.GetString("reqID")
	resp, err := h.authService.RefreshAccessToken(req.RefreshToken, reqID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ForgotPassword
func (h *handler) ForgotPassword(c *gin.Context) {
	var req struct {
		Mobile string `json:"mobile" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	reqID := c.GetString("reqID")
	code, err := h.authService.ForgotPassword(req.Mobile, reqID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": code})
}

// VerifyResetPassword
func (h *handler) VerifyResetPassword(c *gin.Context) {
	var req struct {
		Mobile string `json:"mobile" binding:"required"`
		OTP    string `json:"otp" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	reqID := c.GetString("reqID")
	err := h.authService.VerifyResetPassword(req.Mobile, req.OTP, reqID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OTP verified"})
}

// ResetPassword
func (h *handler) ResetPassword(c *gin.Context) {
	var req struct {
		Mobile   string `json:"mobile" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	reqID := c.GetString("reqID")
	err := h.authService.ResetPassword(req.Mobile, req.Password, reqID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}