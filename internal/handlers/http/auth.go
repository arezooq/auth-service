package http

import (
	"github.com/arezooq/open-utils/api"
	"net/http"

	"auth-service/internal/models"
	"github.com/arezooq/open-utils/errors"
	"github.com/gin-gonic/gin"
)

// Login godoc
// @Summary User login
// @Description Authenticate user and get access/refresh tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param login body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse
// @Router /auth/login [post]
func (h *handler) Login(c *gin.Context) {

	req := api.New(c, "auth-service", "v1")

	loginReq := &models.LoginRequest{}

	if err := req.BindJSON(loginReq); err != nil {
		api.FromAppError(c, errors.ErrInvalidateInput, map[string]string{
			"detail": err.Error(),
		})

		return
	}

	result, appErr := h.authService.LoginUser(req, loginReq)
	if appErr != nil {
		api.FromAppError(c, appErr, nil)
		return
	}

	api.Success(c, http.StatusOK, "Login successfully", result)
}

// Register godoc
// @Summary Register new user
// @Description Create a new user account
// @Tags Auth
// @Accept json
// @Produce json
// @Param user body models.User true "User info"
// @Success 201 {object} models.User
// @Router /auth/register [post]
func (h *handler) Register(c *gin.Context) {
	req := api.New(c, "auth-service", "v1")

	user := &models.User{}
	if err := req.BindJSON(user); err != nil {
		api.FromAppError(c, errors.ErrInvalidateInput, map[string]string{
			"detail": err.Error(),
		})

		return
	}

	result, appErr := h.authService.RegisterUser(req, user)
	if appErr != nil {
		api.FromAppError(c, appErr, nil)
		return
	}
	api.Success(c, http.StatusCreated, "User created successfully", result)
}

// Refresh godoc
// @Summary Refresh access token
// @Description Refresh access token using a valid refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param refresh body models.RefreshRequest true "Refresh token payload"
// @Success 200 {object} models.LoginResponse
// @Router /auth/refresh [post]
func (h *handler) Refresh(c *gin.Context) {
	req := api.New(c, "auth-service", "v1")

	var body models.RefreshRequest
	if err := req.BindJSON(&body); err != nil {
		api.FromAppError(c, errors.ErrInvalidateInput, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	resp, appErr := h.authService.RefreshAccessToken(req, body.RefreshToken)
	if appErr != nil {
		api.FromAppError(c, appErr, nil)
		return
	}

	api.Success(c, http.StatusOK, "Access token refreshed successfully", resp)
}

// ForgotPassword godoc
// @Summary Send password reset code
// @Description Send verification code to user's mobile for password reset
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.ForgotPasswordRequest true "Forgot password request"
// @Success 200 {object} models.ForgotPasswordResponse
// @Router /auth/forgot-password [post]
func (h *handler) ForgotPassword(c *gin.Context) {
	req := api.New(c, "auth-service", "v1")

	body := &models.ForgotPasswordRequest{}
	if err := req.BindJSON(body); err != nil {
		api.FromAppError(c, errors.ErrInvalidateInput, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	code, appErr := h.authService.ForgotPassword(req, body.Mobile)
	if appErr != nil {
		api.FromAppError(c, appErr, nil)
		return
	}

	api.Success(c, http.StatusOK, "Verification code sent successfully", models.ForgotPasswordResponse{
		Code: code,
	})
}

// VerifyResetPassword godoc
// @Summary Verify reset password OTP
// @Description Verify OTP sent for password reset
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.VerifyResetPasswordRequest true "Verify Reset Password Request"
// @Router /auth/verify-reset-password [post]
func (h *handler) VerifyResetPassword(c *gin.Context) {
	req := api.New(c, "auth-service", "v1")

	reqVerify := &models.VerifyResetPasswordRequest{}

	if err := c.ShouldBindJSON(reqVerify); err != nil {
		api.FromAppError(c, errors.ErrBadRequest, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	err := h.authService.VerifyResetPassword(req, reqVerify)
	if err != nil {
		api.FromAppError(c, errors.ErrUnauthorized, map[string]string{
			"detail": err.Error(),
		})
	}

	api.Success(c, http.StatusOK, "OTP verified", nil)
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Verify OTP and reset the user password
// @Tags Auth
// @Accept json
// @Produce json
// @Produce json
// @Param request body models.ResetPasswordRequest true "Reset Password Request"
// @Router /auth/reset-password [post]
func (h *handler) ResetPassword(c *gin.Context) {
	req := api.New(c, "auth-service", "v1")

	resetPass := &models.ResetPasswordRequest{}
	if err := req.BindJSON(resetPass); err != nil {
		api.FromAppError(c, errors.ErrInvalidateInput, map[string]string{
			"detail": err.Error(),
		})

		return
	}
	err := h.authService.ResetPassword(req, resetPass)
	if err != nil {
		api.FromAppError(c, err, nil)
		return
	}
	if err != nil {
		api.FromAppError(c, errors.ErrInternal, map[string]string{
			"detail": err.Error(),
		})
	}
	api.Success(c, http.StatusOK, "Password reset successful", nil)
}

// OAuthLogin godoc
// @Summary Login with OAuth provider
// @Description Login or register a user using OAuth (e.g., Google, GitHub, etc.)
// @Tags Auth
// @Accept json
// @Produce json
// @Param data body models.OAuthLoginRequest true "OAuth Login Request"
// @Success 200 {object} models.OAuthLoginResponse
// @Router /auth/oauth/login [post]
func (h *handler) OAuthLogin(c *gin.Context) {
	req := api.New(c, "auth-service", "v1")

	oAuthLogin := &models.OAuthLoginRequest{}
	if err := req.BindJSON(oAuthLogin); err != nil {
		api.FromAppError(c, errors.ErrInvalidateInput, map[string]string{
			"detail": err.Error(),
		})

		return
	}

	result, appErr := h.authService.OAuthLogin(req, oAuthLogin)
	if appErr != nil {
		api.FromAppError(c, appErr, nil)
		return
	}

	api.Success(c, http.StatusOK, "Login successfully", result)
}
