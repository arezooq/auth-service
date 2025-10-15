package services

import (
	"github.com/arezooq/open-utils/api"
	"time"

	"auth-service/internal/api/oauth"
	"auth-service/internal/models"

	"auth-service/internal/api/user"
	"auth-service/internal/repositories/redis"

	"github.com/arezooq/open-utils/errors"
	"github.com/arezooq/open-utils/jwt"
	"github.com/arezooq/open-utils/logger"
	"github.com/arezooq/open-utils/security"
)

type OAuthUserInfo struct {
	Email string
	Name  string
	ID    string
}

type authService struct {
	otpRepo     *redis.OTPRepository
	user        *user.UserClient
	log         *logger.Logger
	oauthClient oauth.OAuthClient
}

// NewUserService
func NewAuthService(
	otpRepo *redis.OTPRepository,
	log *logger.Logger,
) AuthService {
	return &authService{otpRepo: otpRepo, log: log}
}

func (s *authService) RegisterUser(req *api.Request, user *models.User) (*models.User, error) {

	existing, _ := s.user.GetUserByEmail(user.Email)
	if existing != nil {
		s.log.Warn("User already exist: " + user.Email)
		return nil, errors.ErrDuplicate
	}

	hashedPassword, errPass := security.HashPassword(user.Password)
	if errPass != nil {
		s.log.Error("Failed to hash password for: " + errPass.Error())
		return nil, errors.ErrInternal
	}

	user.Password = hashedPassword

	err := s.user.Create(user)

	if err != nil {
		s.log.Error("Failed to save user: " + err.Error())
		return nil, errors.ErrInternal
	}
	s.log.Info("Register new user successfully: " + user.Email)
	return user, nil
}

func (s *authService) LoginUser(req *api.Request, loginReq *models.LoginRequest) (*models.LoginResponse, error) {
	user, errUserExist := s.user.GetUserByEmail(loginReq.Email)
	if errUserExist != nil {
		return nil, errors.ErrNotFound
	}

	if !security.CheckPasswordHash(user.Password, loginReq.Password) {
		return nil, errors.ErrUnauthorized
	}

	accessToken, errTok := jwt.GenerateAccessToken(user.ID)
	if errTok != nil {
		s.log.Error("Failed to generate access token: " + errTok.Error())
		return nil, errors.ErrInternal
	}

	refreshToken, errRefTok := jwt.GenerateRefreshToken(user.ID)
	if errRefTok != nil {
		s.log.Error("Failed to generate refresh token: " + errRefTok.Error())
		return nil, errors.ErrInternal
	}

	return &models.LoginResponse{
		ID:           user.ID,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) SendOTP(req *api.Request, mobile string) (string, error) {
	_, err := s.user.GetUserByEmail(mobile)
	if err != nil {
		s.log.Warn("User not found for mobile: " + mobile)
		return "", errors.ErrNotFound
	}

	code, errRedis := s.GenerateAndSaveOTP(mobile, 6, 2*time.Minute)
	if errRedis != nil {
		s.log.Error("Failed to save OTP in Redis: " + errRedis.Error())
		return "", errRedis
	}

	s.log.Info("OTP sent successfully to: " + mobile)
	return code, nil
}

func (s *authService) ForgotPassword(req *api.Request, mobile string) (string, error) {
	user, errUser := s.user.GetUserByEmail(mobile)
	if errUser != nil || user == nil {
		s.log.Warn("User not found for password reset: " + mobile)
		return "", errors.ErrNotFound
	}

	code, errRedis := s.GenerateAndSaveOTP("reset:"+mobile, 6, 10*time.Minute)
	if errRedis != nil {
		s.log.Error("Failed to save OTP in Redis: " + errRedis.Error())
		return "", errRedis
	}

	s.log.Info("Password reset OTP sent successfully to: " + mobile)
	return code, nil
}

func (s *authService) VerifyResetPassword(req *api.Request, reqVerify *models.VerifyResetPasswordRequest) error {
	storedOTP, err := s.otpRepo.VerifyOTP("reset:"+reqVerify.Mobile, reqVerify.OTP)
	if err != nil || !storedOTP {
		s.log.Warn("Invalid or expired reset OTP for: " + reqVerify.Mobile)
		return errors.ErrUnauthorized
	}

	if errDel := s.otpRepo.DeleteOTP("reset:" + reqVerify.Mobile); errDel != nil {
		s.log.Error("Failed to delete reset OTP: " + errDel.Error())
	}

	s.log.Info("Password reset OTP verified successfully for: " + reqVerify.Mobile)
	return nil
}

func (s *authService) ResetPassword(req *api.Request, resetPass *models.ResetPass) error {
	user, errUser := s.user.GetUserByEmail(resetPass.Mobile)
	if errUser != nil || user == nil {
		return errors.ErrNotFound
	}

	hashedPassword, errPass := security.HashPassword(resetPass.Password)
	if errPass != nil {
		s.log.Error("Failed to hash new password: " + errPass.Error())
		return errors.ErrInternal
	}

	updates := map[string]any{
		"password": hashedPassword,
	}
	errUpdate := s.user.Update(user.ID, updates)
	if errUpdate != nil {
		s.log.Error("Failed to update password: " + errUpdate.Error())
		return errors.ErrInternal
	}

	s.log.Info("Password reset successfully for user: " + resetPass.Mobile)
	return nil
}

func (s *authService) RefreshAccessToken(req *api.Request, refreshToken string) (*models.LoginResponse, error) {
	// 1. Validate refresh token
	claims, err := jwt.ValidateRefreshToken(refreshToken)
	if err != nil {
		s.log.Warn("Invalid refresh token: " + err.Error())
		return nil, errors.ErrUnauthorized
	}

	userID := claims.UserID

	// 2. Check refresh token in Redis
	stored, err := s.otpRepo.GetRefreshToken(userID)
	if err != nil || stored != refreshToken {
		s.log.Warn("Refresh token not found or mismatch")
		return nil, errors.ErrUnauthorized
	}

	// 3. Generate new tokens
	accessToken, errAcc := jwt.GenerateAccessToken(userID)
	if errAcc != nil {
		return nil, errors.ErrInternal
	}

	newRefreshToken, errRef := jwt.GenerateRefreshToken(userID)
	if errRef != nil {
		return nil, errors.ErrInternal
	}

	// 4. Replace old refresh token in Redis
	err = s.otpRepo.SaveRefreshToken(userID, newRefreshToken, 7*24*time.Hour)
	if err != nil {
		s.log.Error("Failed to save refresh token: " + err.Error())
		return nil, errors.ErrInternal
	}

	// 5. Return response
	return &models.LoginResponse{
		ID:           userID,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *authService) GenerateAndSaveOTP(key string, length int, ttl time.Duration) (string, error) {
	otp := security.GenerateOTP(length)

	code, errRedis := s.otpRepo.SaveOTP(key, otp, ttl)
	if errRedis != nil {
		s.log.Error("Failed to save OTP in Redis: " + errRedis.Error())
		return "", errors.ErrInternal
	}

	return code, nil
}

func (s *authService) OAuthLogin(req *api.Request, oAuthLogin *models.OAuthLoginRequest) (*models.OAuthLoginResponse, error) {
	userInfo, err := s.oauthClient.GetUserInfo(req.Ctx, oAuthLogin.Provider, oAuthLogin.Token)
	if err != nil {
		return nil, err
	}
	// If user exist -> fetch user
	user, err := s.user.GetUserByEmail(userInfo.Email)
	if err != nil {
		// If user not exist -> create user
		user = &models.User{Email: userInfo.Email, FName: userInfo.Name}
		err = s.user.Create(user)
		if err != nil {
			return nil, err
		}
	}

	// Generate accessToken
	accessToken, errTok := jwt.GenerateAccessToken(user.ID)
	if errTok != nil {
		s.log.Error("Failed to generate access token: " + errTok.Error())
		return nil, errors.ErrInternal
	}

	// Generate refreshToken
	refreshToken, errRefTok := jwt.GenerateRefreshToken(user.ID)
	if errRefTok != nil {
		s.log.Error("Failed to generate refresh token: " + errRefTok.Error())
		return nil, errors.ErrInternal
	}

	return &models.OAuthLoginResponse{
		ID:           user.ID,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
