package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"oauth_app/internal/config"
	"oauth_app/internal/server"
	"oauth_app/pkg/keycloak"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

func main() {

	// Настройка форматирования с цветами
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,                  // Принудительно включаем цвета
		FullTimestamp:   true,                  // Показывать полную метку времени
		TimestampFormat: "2006-01-02 15:04:05", // Формат времени
	})

	logrus.SetLevel(logrus.DebugLevel)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logrus.Fatalf("failed to load and parse config : %v", err)
		return
	}
	serverAddr := fmt.Sprintf("%s:%s", cfg.AppHost, cfg.AppPort)
	ctx := context.Background()

	authClient, err := keycloak.New(ctx, cfg.KkAuth)
	if err != nil {
		logrus.Fatalf("Failed to initialize auth client : %v", err)
		return
	}
	// Redis
	redisClient := redis.NewClient(&cfg.RedisConfig)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logrus.Fatalf("failed to connect to Redis: %v", err)
		return
	}
	defer redisClient.Close()

	srv := server.NewServer(ctx, serverAddr, cfg, authClient, redisClient)

	// Запускаем сервер в горутине
	go func() {
		if err := srv.Run(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("listen: %s\n", err)
		}
	}()

	// Ожидаем сигналы завершения
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrus.Println("Shutting down server...")

	// Создаем контекст с таймаутом для graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logrus.Fatal("Server forced to shutdown:", err)
	}

	if err := redisClient.Close(); err != nil {
		logrus.Error(err.Error())
	}

	logrus.Println("Server exiting")
}
