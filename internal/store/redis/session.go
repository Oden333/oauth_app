package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"oauth_app/internal/store"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisSessionManager struct {
	client      *redis.Client
	PrefixState string
	defaultTTL  time.Duration
}

func NewSessionRedisManager(rds *redis.Client) *RedisSessionManager {
	return &RedisSessionManager{
		client:      rds,
		PrefixState: "session",
		defaultTTL:  5 * time.Minute,
	}
}
func (s *RedisSessionManager) buildKey(userID string) string {
	return fmt.Sprintf("%s:%s", s.PrefixState, userID)
}

// SaveSession stores session data in Redis
func (s *RedisSessionManager) SaveSession(ctx context.Context,
	userID string,
	session *store.SessionData) error {
	jsonData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("error marshaling session data: %w", err)
	}

	key := s.buildKey(userID)
	err = s.client.SetEx(ctx, key, string(jsonData), s.defaultTTL).Err()
	if err != nil {
		return fmt.Errorf("error saving session to redis: %w", err)
	}

	return nil
}

// GetSession retrieves session data from Redis
func (s *RedisSessionManager) GetSession(ctx context.Context, userID string) (*store.SessionData, error) {
	key := s.buildKey(userID)

	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting session from redis: %w", err)
	}

	var session store.SessionData
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("error unmarshaling session data: %w", err)
	}

	return &session, nil
}

// DeleteSession removes session from Redis
func (s *RedisSessionManager) DeleteSession(ctx context.Context, userID string) error {
	key := s.buildKey(userID)
	err := s.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("error deleting session from redis: %w", err)
	}

	return nil
}

// CheckSession verifies if a session exists
func (s *RedisSessionManager) CheckSession(ctx context.Context, userID string) (bool, error) {
	key := s.buildKey(userID)
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("error checking session existence: %w", err)
	}

	return exists == 1, nil
}
