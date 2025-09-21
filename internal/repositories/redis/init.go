package redis

import (
	"context"
	"auth-service/internal/constant"
	"os"

	"github.com/arezooq/open-utils/db/connection"
	"github.com/redis/go-redis/v9"
)

func InitRedis(ctx context.Context) (*redis.Client, error) {
    cfg := connection.RedisConfig{
        Addr:     constant.REDIS_HOST + ":" + os.Getenv("REDIS_PORT"),
        Password: constant.REDIS_PASSWORD,
        DB:       0,
        PoolSize: 10,
    }

    return connection.ConnectRedis(ctx, cfg)
}

