package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Client struct {
	Provider *oidc.Provider
	OIDC     *oidc.IDTokenVerifier
	Oauth    oauth2.Config
}
type Config struct {
	BaseURL      string // Authorization base url
	ClientID     string // client id oauth
	RedirectURL  string // valid redirect url
	ClientSecret string // optional
	Realm        string // keycloak realm
}
type Option func(*Config)

func New(ctx context.Context, baseURLAuthServer, clientID, redirectURL string, options ...Option) (*Client, error) {

	config := &Config{
		BaseURL:     baseURLAuthServer,
		ClientID:    clientID,
		RedirectURL: redirectURL,
	}
	// Apply all provided options
	for _, opt := range options {
		opt(config)
	}

	// Construct the provider URL using Keycloak realm
	providerURL := fmt.Sprintf("%s/realms/%s", config.BaseURL, config.Realm)

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}
	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	// Configure an OpenID Connect aware OAuth2 client
	oauth2 := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "roles"},
	}
	return &Client{
		Oauth:    oauth2,
		OIDC:     verifier,
		Provider: provider,
	}, nil
}

func WithClientSecret(clientSecret string) Option {
	return func(c *Config) {
		c.ClientSecret = clientSecret
	}
}
func WithRealmKeycloak(realm string) Option {
	return func(c *Config) {
		c.Realm = realm
	}
}
