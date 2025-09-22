package main

import (
	"context"
	"os"

	"github.com/gin-gonic/gin"

	"auth-service/internal/handlers/http"
	"auth-service/internal/repositories/postgres"
	"auth-service/internal/repositories/redis"
	"auth-service/internal/services"
	"github.com/arezooq/open-utils/logger"
)

func main() {
	port := os.Getenv("PORT")
	var ctx context.Context

	logger := logger.New("auth-service")

	// redis
	redisRepo, err := redis.InitRedis(ctx)
	if err != nil {
		logger.Fatal("-", "failed to init redis: "+err.Error())
	}

	// Postgres
	pgDB, err := postgres.InitPostgres()
	if err != nil {
		logger.Fatal("-", "failed to init postgres: "+err.Error())
	}

	otpRepo := redis.NewOTPRepository(redisRepo, ctx)
	userRepo := postgres.NewUserRepository(pgDB, logger)

	authService := services.NewAuthService(otpRepo, userRepo, logger)
	authHandler := http.InitAuthHandler(authService)

	r := gin.Default()
	authHandler.RegisterRoutes(r)
	logger.Info("-", "Server started on port "+port)
	r.Run(":" + port)
}
