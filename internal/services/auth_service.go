package serivces

import (
	"time"

	"github.com/arezooq/auth-serivce/internal/models"

	"github.com/arezooq/auth-serivce/internal/repositories"
	"github.com/arezooq/open-utils/errors"
	"github.com/arezooq/open-utils/jwt"
	"github.com/arezooq/open-utils/logger"
	"github.com/arezooq/open-utils/security"
	"github.com/google/uuid"
)

type AuthService struct {
	otpRepo  *repositories.OTPRepository
	userRepo *repositories.UserRepository
	log      *logger.Logger
}

// NewUserService
func NewAuthService(userRepo *repositories.UserRepository, otpRepo *repositories.OTPRepository, log *logger.Logger) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		otpRepo:  otpRepo,
		log:      log,
	}
}

type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
}

func (s *AuthService) RegisterUser(user *models.User, reqID string) (*models.User, error) {

	existing, _ := s.userRepo.GetUserByEmailOrPhone(user.Email, reqID)
	if existing != nil {
		s.log.Warn(reqID, "User already exist: "+user.Email)
		return nil, errors.ErrDuplicate
	}

	hashedPassword, errPass := security.HashPassword(user.Password)
	if errPass != nil {
		s.log.Error(reqID, "Failed to hash password for: "+errPass.Error())
		return nil, errors.ErrInternal
	}

	user.Password = hashedPassword

	user, err := s.userRepo.Create(user)

	if err != nil {
		s.log.Error(reqID, "Failed to save user: "+err.Error())
		return nil, errors.ErrInternal
	}
	s.log.Info(reqID, "Register new user successfully: "+user.Email)
	return user, nil
}

func (s *AuthService) LoginUser(email, password, reqID string) (*LoginResponse, error) {
	user, errUserExist := s.userRepo.GetUserByEmailOrPhone(email, reqID)
	if errUserExist != nil {
		return nil, errors.ErrNotFound
	}

	if !security.CheckPasswordHash(user.Password, password) {
		return nil, errors.ErrUnauthorized
	}

	accessToken, errTok := jwt.GenerateAccessToken(user.ID)
	if errTok != nil {
		s.log.Error(reqID, "Failed to generate access token: "+errTok.Error())
		return nil, errors.ErrInternal
	}

	refreshToken, errRefTok := jwt.GenerateRefreshToken(user.ID)
	if errRefTok != nil {
		s.log.Error(reqID, "Failed to generate refresh token: "+errRefTok.Error())
		return nil, errors.ErrInternal
	}

	return &LoginResponse{
		ID:           user.ID,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) SendOTP(mobile string, reqID string) (string, error) {
	_, err := s.userRepo.GetUserByEmailOrPhone(mobile, reqID)
	if err != nil {
		s.log.Warn(reqID, "User not found for mobile: "+mobile)
		return "", errors.ErrNotFound
	}

	code, errRedis := s.generateAndSaveOTP(mobile, 6, 2*time.Minute, reqID)
	if errRedis != nil {
		s.log.Error(reqID, "Failed to save OTP in Redis: "+errRedis.Error())
		return "", errRedis
	}

	s.log.Info(reqID, "OTP sent successfully to: "+mobile)
	return code, nil
}

func (s *AuthService) ForgotPassword(mobile, reqID string) (string, error) {
	user, errUser := s.userRepo.GetUserByEmailOrPhone(mobile, reqID)
	if errUser != nil || user == nil {
		s.log.Warn(reqID, "User not found for password reset: "+mobile)
		return "", errors.ErrNotFound
	}

	code, errRedis := s.generateAndSaveOTP("reset:"+mobile, 6, 10*time.Minute, reqID)
	if errRedis != nil {
		s.log.Error(reqID, "Failed to save OTP in Redis: "+errRedis.Error())
		return "", errRedis
	}

	s.log.Info(reqID, "Password reset OTP sent successfully to: "+mobile)
	return code, nil
}

func (s *AuthService) VerifyResetPassword(mobile, otp, reqID string) error {
	storedOTP, err := s.otpRepo.VerifyOTP("reset:"+mobile, otp)
	if err != nil || !storedOTP {
		s.log.Warn(reqID, "Invalid or expired reset OTP for: "+mobile)
		return errors.ErrUnauthorized
	}

	if errDel := s.otpRepo.DeleteOTP("reset:" + mobile); errDel != nil {
		s.log.Error(reqID, "Failed to delete reset OTP: "+errDel.Error())
	}

	s.log.Info(reqID, "Password reset OTP verified successfully for: "+mobile)
	return nil
}

func (s *AuthService) ResetPassword(mobile, newPassword, reqID string) error {
	user, errUser := s.userRepo.GetUserByEmailOrPhone(mobile, reqID)
	if errUser != nil || user == nil {
		return errors.ErrNotFound
	}

	hashedPassword, errPass := security.HashPassword(newPassword)
	if errPass != nil {
		s.log.Error(reqID, "Failed to hash new password: "+errPass.Error())
		return errors.ErrInternal
	}

	updates := map[string]any{
		"password": hashedPassword,
	}
	_, errUpdate := s.userRepo.Update(user.ID, updates)
	if errUpdate != nil {
		s.log.Error(reqID, "Failed to update password: "+errUpdate.Error())
		return errors.ErrInternal
	}

	s.log.Info(reqID, "Password reset successfully for user: "+mobile)
	return nil
}

func (s *AuthService) RefreshAccessToken(refreshToken, reqID string) (*LoginResponse, error) {
	// 1. Validate refresh token
	claims, err := jwt.ValidateRefreshToken(refreshToken)
	if err != nil {
		s.log.Warn(reqID, "Invalid refresh token: "+err.Error())
		return nil, errors.ErrUnauthorized
	}

	userID := claims.UserID

	// 2. Check refresh token in Redis
	stored, err := s.otpRepo.GetRefreshToken(userID.String())
	if err != nil || stored != refreshToken {
		s.log.Warn(reqID, "Refresh token not found or mismatch")
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
	err = s.otpRepo.SaveRefreshToken(userID.String(), newRefreshToken, 7*24*time.Hour)
	if err != nil {
		s.log.Error(reqID, "failed to save refresh token: "+ err.Error())
		return nil, errors.ErrInternal
	}

	// 5. Return response
	return &LoginResponse{
		ID:           userID,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *AuthService) generateAndSaveOTP(key string, length int, ttl time.Duration, reqID string) (string, error) {
	otp := security.GenerateOTP(length)

	code, errRedis := s.otpRepo.SaveOTP(key, otp, ttl)
	if errRedis != nil {
		s.log.Error(reqID, "Failed to save OTP in Redis: "+errRedis.Error())
		return "", errors.ErrInternal
	}

	return code, nil
}
