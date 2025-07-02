package authhandler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"oauth_app/internal/store"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func (a *AuthHandler) CallbackHandler(c *gin.Context) {
	if err := a.validateStateSession(c); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate state session"})
		return
	}
	oauthToken, err := a.tokenExchange(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}
	userInfo, err := a.validateAndGetClaimsIDToken(c, oauthToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": "Failed to validate and get claims id token"})
		return
	}
	sessionID, err := generateRandomSecureString()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session ID"})
		return
	}
	// Create session data
	sessionData := &store.SessionData{
		AccessToken: oauthToken.AccessToken, // From Keycloak
		UserInfoData: &store.UserInfoData{
			FullName: userInfo.Username,
			Email:    userInfo.Email,
		},
		// CreatedAt: time.Now(),
	}

	// Store session
	if err := a.sessionStore.SaveSession(c, sessionID, sessionData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store session"})
		return
	}
	// Note: Gin handles SameSite through the Config struct
	c.SetSameSite(http.SameSiteStrictMode)
	// Set secure session cookie using Gin's methods
	c.SetCookie(
		"session_id",                 // name
		sessionID,                    // value
		int(5*time.Minute.Seconds()), // maxAge in seconds
		"/",                          // path
		"",                           // domain (empty means default to current domain)
		true,                         // Set secure to false for HTTP development
		true,                         // httpOnly (prevents JavaScript access)
	)

	// Redirect to dashboard using Gin's redirect method
	c.Redirect(http.StatusTemporaryRedirect, "/dashboard")
}
func (a *AuthHandler) validateStateSession(c *gin.Context) error {
	// Get state from callback parameters
	stateParam := c.Query("state")
	if stateParam == "" {
		return errors.New("missing state parameter in callback")
	}

	// Retrieve stored state from Redis
	storedState, err := a.authStore.GetState(c, stateParam)
	if err != nil {
		return fmt.Errorf("failed to retrieve stored state: %w", err)
	}

	// Validate state match
	if storedState != stateParam {
		return errors.New("state parameter mismatch")
	}

	// Clean up used state from store
	if err = a.authStore.DeleteState(c, storedState); err != nil {
		log.Printf("Warning: failed to delete used state: %v", err)
	}

	return nil
}
func (a *AuthHandler) tokenExchange(c *gin.Context) (*oauth2.Token, error) {
	authorizationCode := c.Query("code")
	if authorizationCode == "" {
		return nil, errors.New("authorizationCode is required")
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("grant_type", "authorization_code"),
	}
	oauth2Token, err := a.authClient.Oauth.Exchange(c, authorizationCode, opts...)
	if err != nil {
		return nil, err
	}
	return oauth2Token, nil
}

type oidcClaims struct {
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
}

// ValidateIDToken verifies the id token from the oauth2token
func (a *AuthHandler) validateAndGetClaimsIDToken(
	c *gin.Context, oauth2Token *oauth2.Token) (*oidcClaims, error) {
	// Get and validate the ID token - this proves the user's identity
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no ID token found")
	}
	// Verify the ID token
	idToken, err := a.authClient.OIDC.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		return nil, errors.New("failed to verify ID token")
	}
	claims := oidcClaims{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.New("failed to get user info")
	}
	return &claims, nil
}

// generateRandomSecureString creates a random secure string
func generateRandomSecureString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
