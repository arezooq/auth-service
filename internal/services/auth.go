package services

import (
	"auth-service/internal/constant"
	"auth-service/internal/models"
	"context"
	"time"
)

type AuthService interface {
	RegisterUser(user *models.User) (*models.User, error)
	LoginUser(email, password string) (*constant.LoginResponse, error)
	SendOTP(mobile string) (string, error)
	ForgotPassword(mobile string) (string, error)
	VerifyResetPassword(mobile, otp string) error
	ResetPassword(mobile, newPassword string) error
	RefreshAccessToken(refreshToken string) (*constant.LoginResponse, error)
	GenerateAndSaveOTP(key string, length int, ttl time.Duration) (string, error)

	OAuthLogin(ctx context.Context, provider, code string) (*constant.LoginResponse, error)
}
