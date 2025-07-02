package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"oauth_app/pkg/keycloak"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type Config struct {
	KkAuth      *keycloak.Config
	RedisConfig redis.Options
	AppPort     string
	AppHost     string
}

func LoadFromEnv() (*Config, error) {
	// Get the absolute path of the current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Construct path to .env file in ../cmd/.env
	envPath := filepath.Join(currentDir, "..", ".env")
	err = godotenv.Load(envPath)

	if err != nil {
		logrus.Fatal("Error loading .env file", err)
	}

	redisDB, err := strconv.Atoi(os.Getenv("REDIS_DATABASE"))
	if err != nil {
		logrus.Fatal("Database redis invalid : ", err)
	}
	return &Config{
		KkAuth: &keycloak.Config{
			BaseURL: os.Getenv("KEYCLOAK_BASE_URL"),
			Realm:   os.Getenv("KEYCLOAK_REALM"),

			ClientID:     os.Getenv("KEYCLOAK_CLIENT_ID"),
			ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),

			RedirectURL: os.Getenv("KEYCLOAK_REDIRECT_URL"),
		},
		RedisConfig: redis.Options{
			Addr: fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
			// Username: os.Getenv("REDIS_USERNAME"),
			// Password: os.Getenv("REDIS_PASSWORD"),
			DB: redisDB,
		},
		AppPort: os.Getenv("APP_PORT"),
		AppHost: os.Getenv("APP_HOST"),
	}, nil
}
