package postgres

import (
	"auth-service/internal/constant"

	"github.com/arezooq/open-utils/db/connection"
	"github.com/arezooq/open-utils/errors"
	"gorm.io/gorm"
)

func InitPostgres() (*gorm.DB, error){
    cfg := connection.DBConfig{
        Host: constant.PostgresAddr,
        Port: constant.HttpPort,
        User: constant.PostgresUsername,
        Password: constant.PostgresPassword,
        DBName: constant.PostgresDatabase,
        SSLMode: constant.PostgresSSLMode,
    }

    DB, err := connection.ConnectDB(cfg)
    if err != nil {
		return nil, errors.New("cannot connect to db: %v", err.Error(), 500)
    }

	return DB, nil
}