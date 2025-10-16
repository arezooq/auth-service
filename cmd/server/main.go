package main

import (
	"context"
	"os"

	_ "auth-service/docs"
	"auth-service/internal/handlers/http"
	"auth-service/internal/repositories/redis"
	"auth-service/internal/services"
	"github.com/arezooq/open-utils/logger"
	"github.com/gin-gonic/gin"
)

// @title Auth Service API
// @version 1.0
// @description This is the Auth Service API documentation.
// @BasePath /api/auth
func main() {
	port := os.Getenv("PORT")
	ctx := context.Background()

	logger := logger.New("auth-service")

	// redis
	redisRepo, err := redis.InitRedis(ctx)
	if err != nil {
		logger.Fatal("Failed to init redis: " + err.Error())
	}

	otpRepo := redis.NewOTPRepository(redisRepo, ctx)

	authService := services.NewAuthService(otpRepo, logger)
	authHandler := http.InitAuthHandler(authService)

	r := gin.Default()
	authHandler.RegisterRoutes(r)
	logger.Info("Server started on port " + port)
	r.Run(":" + port)
}
