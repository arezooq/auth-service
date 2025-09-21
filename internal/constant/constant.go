package constant

import (
	"github.com/joho/godotenv"
	"os"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

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
	HttpPort        = getEnv("POSTGRESDB_PORT")
	PostgresUsername = getEnv("POSTGRESDB_USERNAME")
	PostgresPassword   = getEnv("POSTGRESDB_PASSWORD")
	PostgresAddr       = getEnv("POSTGRESDB_ADDR")
	PostgresDatabase   = getEnv("POSTGRESDB_DATABASE")
	PostgresSSLMode    = getEnv("POSTGRESDB_SSLMODE")
)
