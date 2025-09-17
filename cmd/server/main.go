package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/arezooq/auth-serivce/internal/http"
	"github.com/arezooq/auth-service/internal/repositories"
	"github.com/arezooq/auth-service/internal/services"
)

func main() {
    cfg := configs.Load()

    logger := log.Default()
    redisRepo, err := repositories.InitRedis(cfg)
    if err != nil {
        logger.Fatal("Failed to init redis:", err)
    }

    otpRepo := repositories.NewOTPRepository(redisRepo)
    userRepo := repositories.NewUserRepository()

    authService := services.NewAuthService(userRepo, otpRepo, logger)
    authHandler := http.InitAuthHandler(authService)

    r := gin.Default()
    authHandler.RegisterRoutes(r)
    r.Run(":" + cfg.AppPort)
}
