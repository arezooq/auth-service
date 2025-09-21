package redis

import (
	"context"
	"time"

	"github.com/arezooq/open-utils/db/repository"
	"github.com/arezooq/open-utils/errors"
	"github.com/redis/go-redis/v9"
)

type OTPRepository struct {
	*repository.BaseRedisRepository
}

func NewOTPRepository(client *redis.Client, ctx context.Context) *OTPRepository {
	return &OTPRepository{
		BaseRedisRepository: repository.NewBaseRedisRepository(client, ctx),
	}
}

// Save OTP with TTL
func (o *OTPRepository) SaveOTP(key, code string, ttl time.Duration) (string, error) {
	err := o.BaseRedisRepository.Set(key, code, ttl)
	if err != nil {
		return "", errors.ErrRedis
	}
	return code, nil
}

// Verify OTP and delete if matches
func (o *OTPRepository) VerifyOTP(key, code string) (bool, error) {
	storedCode, err := o.BaseRedisRepository.Get(key)
	if err != nil {
		return false, errors.ErrNotFound
	}

	if storedCode != code {
		return false, errors.ErrUnauthorized
	}

	// optional: delete OTP after verification
	_ = o.BaseRedisRepository.Delete(key)

	return true, nil
}

// Delete OTP manually
func (o *OTPRepository) DeleteOTP(key string) error {
	return o.BaseRedisRepository.Delete(key)
}

// Save Refresh Token with TTL
func (o *OTPRepository) SaveRefreshToken(userID, refreshToken string, ttl time.Duration) error {
	err := o.BaseRedisRepository.Set("refresh:"+userID, refreshToken, ttl)
	if err != nil {
		return errors.ErrRedis
	}
	return nil
}

// Get Refresh Token
func (o *OTPRepository) GetRefreshToken(userID string) (string, error) {
	token, err := o.BaseRedisRepository.Get("refresh:" + userID)
	if err != nil {
		return "", errors.ErrNotFound
	}
	return token, nil
}

// Delete Refresh Token
func (o *OTPRepository) DeleteRefreshToken(userID string) error {
	return o.BaseRedisRepository.Delete("refresh:" + userID)
}
