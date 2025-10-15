package services

import (
	"auth-service/internal/models"
	"github.com/arezooq/open-utils/api"
	"time"
)

type AuthService interface {
	RegisterUser(req *api.Request, user *models.User) (*models.User, error)
	LoginUser(req *api.Request, loginReq *models.LoginRequest) (*models.LoginResponse, error)
	SendOTP(req *api.Request, mobile string) (string, error)
	ForgotPassword(req *api.Request, mobile string) (string, error)
	VerifyResetPassword(req *api.Request, reqVerify *models.VerifyResetPasswordRequest) error
	ResetPassword(req *api.Request, resetPass *models.ResetPass) error
	RefreshAccessToken(req *api.Request, refreshToken string) (*models.LoginResponse, error)
	GenerateAndSaveOTP(key string, length int, ttl time.Duration) (string, error)

	OAuthLogin(req *api.Request, oAuthLogin *models.OAuthLoginRequest) (*models.OAuthLoginResponse, error)
}
