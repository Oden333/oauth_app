package keycloak

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	BaseURL      string // Authorization base url
	ClientID     string // client id oauth
	RedirectURL  string // valid redirect url
	ClientSecret string //
	Realm        string // keycloak realm
}

// Client struct holds all components needed for authentication
type Client struct {
	Provider *oidc.Provider        // Handles OIDC protocol operations with Keycloak
	OIDC     *oidc.IDTokenVerifier // Verifies JWT tokens from Keycloak
	Oauth    oauth2.Config         // Manages OAuth2 flow (authorization codes, tokens)
}

func New(ctx context.Context, config *Config) (*Client, error) {
	// Construct the provider URL using Keycloak realm
	providerURL := fmt.Sprintf("%s/realms/%s", config.BaseURL, config.Realm)

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	// Configure an OpenID Connect aware OAuth2 client with specific scopes:
	// - oidc.ScopeOpenID: Required for OpenID Connect authentication, provides subject ID (sub)
	// - "roles": Keycloak-specific scope to get user roles in the token
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes: []string{
			oidc.ScopeOpenID, // Required for OIDC authentication
			"roles",          // Request user roles from Keycloak
		},
	}

	// Return initialized client with all required components
	return &Client{
		// oauth2Config: Used for OAuth2 operations like:
		// - Generating login URL (AuthCodeURL)
		// - Exchanging auth code for tokens (Exchange)
		// - Managing token refresh
		Oauth: oauth2Config,

		// verifier: Used to validate tokens:
		// - Verifies JWT signature
		// - Validates token claims (exp, iss, aud)
		// - Extracts user information
		OIDC: verifier,

		// provider: Keycloak OIDC provider that:
		// - Provides endpoint URLs (auth, token)
		// - Handles OIDC protocol details
		// - Manages provider metadata
		Provider: provider,
	}, nil
}

// AuthCodeURL generates the login URL for OAuth2 authorization code flow.
// It returns a URL that the user should be redirected to for authentication.
// The state parameter is a random string that will be validated in the callback
// to prevent CSRF attacks.
func (c *Client) AuthCodeURL(state string) string {
	return c.Oauth.AuthCodeURL(state)
}

// Exchange converts an authorization code into OAuth2 tokens.
// This method is called after the user is redirected back from Keycloak
// with an authorization code. It returns:
// - access_token: for accessing protected resources
// - refresh_token: for getting new access tokens
// - id_token: contains user information
func (c *Client) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.Oauth.Exchange(ctx, code)
}

// VerifyIDToken validates and decodes the ID token from the OAuth2 token response.
// It performs several checks:
// - Verifies the token signature
// - Validates token expiration
// - Validates issuer and audience claims
// Returns decoded ID token containing user claims (sub, email, roles, etc)
func (c *Client) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	// Extract raw ID token from OAuth2 token extras
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}
	return c.OIDC.Verify(ctx, rawIDToken)
}
