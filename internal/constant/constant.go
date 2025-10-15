package constant

import (
	"github.com/joho/godotenv"
	"os"
)

// service info
const (
	ServiceName    = "auth-service"
	ServiceVersion = "1.0.0"
)

func getEnv(key string) string {
	_ = godotenv.Load(".env")
	return os.Getenv(key)
}

// postgres
var (
	HttpPort         = getEnv("POSTGRESDB_PORT")
	PostgresUsername = getEnv("POSTGRESDB_USERNAME")
	PostgresPassword = getEnv("POSTGRESDB_PASSWORD")
	PostgresAddr     = getEnv("POSTGRESDB_ADDR")
	PostgresDatabase = getEnv("POSTGRESDB_DATABASE")
	PostgresSSLMode  = getEnv("POSTGRESDB_SSLMODE")
)

// redis
var (
	REDIS_HOST     = getEnv("REDIS_HOST")
	REDIS_PASSWORD = getEnv("REDIS_PASSWORD")
)
