package http_test

import (
	httphandler "auth-service/internal/handlers/http"
	"bytes"
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"auth-service/internal/constant"
	"auth-service/internal/models"
)

type MockAuthService struct {
	RegisterUserFn        func(user *models.User) (*models.User, error)
	LoginUserFn           func(email, password string) (*constant.LoginResponse, error)
	SendOTPFn             func(mobile string) (string, error)
	ForgotPasswordFn      func(mobile string) (string, error)
	VerifyResetPasswordFn func(mobile, otp string) error
	ResetPasswordFn       func(mobile, newPassword string) error
	RefreshAccessTokenFn  func(refreshToken string) (*constant.LoginResponse, error)
	GenerateAndSaveOTPFn  func(key string, length int, ttl time.Duration) (string, error)
	OAuthLoginFn            func(ctx context.Context, provider, code string) (*constant.LoginResponse, error)
}

// Implement all methods
func (m *MockAuthService) RegisterUser(user *models.User) (*models.User, error) {
	return m.RegisterUserFn(user)
}

func (m *MockAuthService) LoginUser(email, password string) (*constant.LoginResponse, error) {
	return m.LoginUserFn(email, password)
}

func (m *MockAuthService) SendOTP(mobile string) (string, error) {
	return m.SendOTPFn(mobile)
}

func (m *MockAuthService) ForgotPassword(mobile string) (string, error) {
	return m.ForgotPasswordFn(mobile)
}

func (m *MockAuthService) VerifyResetPassword(mobile, otp string) error {
	return m.VerifyResetPasswordFn(mobile, otp)
}

func (m *MockAuthService) ResetPassword(mobile, newPassword string) error {
	return m.ResetPasswordFn(mobile, newPassword)
}

func (m *MockAuthService) RefreshAccessToken(refreshToken string) (*constant.LoginResponse, error) {
	return m.RefreshAccessTokenFn(refreshToken)
}
func (m *MockAuthService) GenerateAndSaveOTP(key string, length int, ttl time.Duration) (string, error) {
	return m.GenerateAndSaveOTPFn(key, length, ttl)
}

func (m *MockAuthService) OAuthLogin(ctx context.Context, provider, code string) (*constant.LoginResponse, error) {
	return m.OAuthLoginFn(ctx, provider, code)
}

// Register
func TestRegister_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &MockAuthService{
		RegisterUserFn: func(user *models.User) (*models.User, error) {
			return &models.User{ID: uuid.New(), Email: user.Email}, nil
		},
	}

	h := httphandler.InitAuthHandler(mockSvc)

	body, _ := json.Marshal(models.User{Email: "test@example.com", Password: "pass"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	r := gin.New()
	h.RegisterRoutes(r)
	r.ServeHTTP(w, req)

	assert.Equal(t, 201, w.Code)
	assert.Contains(t, w.Body.String(), "test@example.com")
}

// Login
func TestLogin_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &MockAuthService{
		LoginUserFn: func(email, password string) (*constant.LoginResponse, error) {
			return &constant.LoginResponse{
				ID:           uuid.New(),
				Email:        email,
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
			}, nil
		},
	}

	h := httphandler.InitAuthHandler(mockSvc)

	body, _ := json.Marshal(map[string]string{"email": "test@example.com", "password": "pass"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	r := gin.New()
	h.RegisterRoutes(r)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "access-token")
}

// Send OTP
func TestSendOTP_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &MockAuthService{
		SendOTPFn: func(mobile string) (string, error) {
			return "123456", nil
		},
	}

	h := httphandler.InitAuthHandler(mockSvc)

	body, _ := json.Marshal(map[string]string{"mobile": "09120000000"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/send-otp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	r := gin.New()
	h.RegisterRoutes(r)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "123456")
}

// Forgot Password
func TestForgotPassword_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &MockAuthService{
		ForgotPasswordFn: func(mobile string) (string, error) {
			return "reset-otp", nil
		},
	}

	h := httphandler.InitAuthHandler(mockSvc)

	body, _ := json.Marshal(map[string]string{"mobile": "09120000000"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	r := gin.New()
	h.RegisterRoutes(r)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "reset-otp")
}

// Refresh Token
func TestRefreshToken_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &MockAuthService{
		RefreshAccessTokenFn: func(refreshToken string) (*constant.LoginResponse, error) {
			return &constant.LoginResponse{
				ID:           uuid.New(),
				Email:        "user@example.com",
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
			}, nil
		},
	}

	h := httphandler.InitAuthHandler(mockSvc)

	body, _ := json.Marshal(map[string]string{"refresh_token": "old-refresh"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/refresh-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	r := gin.New()
	h.RegisterRoutes(r)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "new-access")
}

func TestOAuthLogin_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockSvc := &MockAuthService{
		OAuthLoginFn: func(ctx context.Context, provider, code string) (*constant.LoginResponse, error) {
			return &constant.LoginResponse{
				ID:           uuid.New(),
				Email:        "test@example.com",
				AccessToken:  "oauth-access",
				RefreshToken: "oauth-refresh",
			}, nil
		},
	}

	h := httphandler.InitAuthHandler(mockSvc)

	reqBody := map[string]string{
		"provider":     "google",
		"access_token": "dummy-token",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := nethttp.NewRequest("POST", "/api/auth/oauth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	r := gin.New()
	h.RegisterRoutes(r)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "oauth-access")
}
