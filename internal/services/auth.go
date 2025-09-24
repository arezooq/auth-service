package services

import (
	"auth-service/internal/constant"
	"auth-service/internal/models"
	"context"
	"time"
)

type AuthService interface {
	RegisterUser(user *models.User, reqID string) (*models.User, error)
	LoginUser(email, password, reqID string) (*constant.LoginResponse, error)
	SendOTP(mobile string, reqID string) (string, error)
	ForgotPassword(mobile, reqID string) (string, error)
	VerifyResetPassword(mobile, otp, reqID string) error
	ResetPassword(mobile, newPassword, reqID string) error
	RefreshAccessToken(refreshToken, reqID string) (*constant.LoginResponse, error)
	GenerateAndSaveOTP(key string, length int, ttl time.Duration, reqID string) (string, error)

	OAuthLogin(ctx context.Context, provider, code, reqID string) (*constant.LoginResponse, error)
}
