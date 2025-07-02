package store

import "context"

// UserInfoData represents user information
type UserInfoData struct {
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

// SessionData represents the complete session information
type SessionData struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	UserInfoData *UserInfoData `json:"user_info_data"`
}

// SessionStore defines the interface for session management
type SessionStore interface {
	SaveSession(ctx context.Context, userID string, session *SessionData) error
	GetSession(ctx context.Context, userID string) (*SessionData, error)
	DeleteSession(ctx context.Context, userID string) error
	CheckSession(ctx context.Context, userID string) (bool, error)
}
