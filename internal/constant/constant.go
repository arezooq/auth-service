package constant

import (
	"os"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

// LoginRequest
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse
type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
}

type OAuthResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
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
