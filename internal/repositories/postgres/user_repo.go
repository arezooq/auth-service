package postgres

import (
	"auth-service/internal/models"
	"github.com/arezooq/open-utils/db/repository"
	"github.com/arezooq/open-utils/errors"
	"github.com/arezooq/open-utils/logger"
	"gorm.io/gorm"
)



type UserRepository struct {
	*repository.BasePostgresRepository[models.User]
	logger *logger.Logger
}

func NewUserRepository(gromDB *gorm.DB, log *logger.Logger) *UserRepository {
	return &UserRepository{
		BasePostgresRepository: &repository.BasePostgresRepository[models.User]{DB: gromDB},
		logger:                 log,
	}
}

// GetByEmailOrPhone
func (u *UserRepository) GetUserByEmailOrPhone(identifier string, reqID string) (*models.User, error) {
	var user models.User
	result := u.DB.Where("email = ? OR phone = ?", identifier, identifier).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			u.logger.Error(reqID, "User not found with identifier: "+identifier)
			return nil, errors.ErrNotFound
		}
		u.logger.Error(reqID, "Failed to fetch user by identifier: "+result.Error.Error())
		return nil, errors.ErrInternal
	}
	return &user, nil
}