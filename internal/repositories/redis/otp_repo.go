package repositories

import (
	"time"

	"github.com/arezooq/open-utils/errors"
	"github.com/arezooq/open-utils/db/repository"
)

type OTPRepository struct {
	redis *repository.BaseRedisRepository
}

func NewOTPRepository(redisRepo *repository.BaseRedisRepository) *OTPRepository {
	return &OTPRepository{redis: redisRepo}
}

// Save OTP with TTL
func (o *OTPRepository) SaveOTP(key, code string, ttl time.Duration) (string, error) {
	err := o.redis.Set(key, code, ttl)
	if err != nil {
		return "", errors.ErrRedis
	}
	return code, nil
}

// Verify OTP and delete if matches
func (o *OTPRepository) VerifyOTP(key, code string) (bool, error) {
	storedCode, err := o.redis.Get(key)
	if err != nil {
		return false, errors.ErrNotFound
	}

	if storedCode != code {
		return false, errors.ErrUnauthorized
	}

	// optional: delete OTP after verification
	_ = o.redis.Delete(key)

	return true, nil
}

// Delete OTP manually
func (o *OTPRepository) DeleteOTP(key string) error {
	return o.redis.Delete(key)
}

// Save Refresh Token with TTL
func (o *OTPRepository) SaveRefreshToken(userID, refreshToken string, ttl time.Duration) error {
    err := o.redis.Set("refresh:"+userID, refreshToken, ttl)
    if err != nil {
        return errors.ErrRedis
    }
    return nil
}

// Get Refresh Token
func (o *OTPRepository) GetRefreshToken(userID string) (string, error) {
    token, err := o.redis.Get("refresh:" + userID)
    if err != nil {
        return "", errors.ErrNotFound
    }
    return token, nil
}

// Delete Refresh Token
func (o *OTPRepository) DeleteRefreshToken(userID string) error {
    return o.redis.Delete("refresh:" + userID)
}

