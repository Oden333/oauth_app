package authhandler

import (
	"fmt"
	"net/http"
	"oauth_app/internal/config"
	"oauth_app/internal/store"
	"oauth_app/internal/utils"
	"oauth_app/pkg/keycloak"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	cfg          *config.Config
	serverAddr   string
	authClient   *keycloak.Client
	authStore    store.AuthStore
	sessionStore store.SessionStore
}

func New(
	cfg *config.Config,
	serverAddr string,
	authClient *keycloak.Client,

	authStore store.AuthStore,
	sessionStore store.SessionStore,
) *AuthHandler {
	return &AuthHandler{
		cfg:          cfg,
		serverAddr:   serverAddr,
		authClient:   authClient,
		authStore:    authStore,
		sessionStore: sessionStore,
	}
}

func (a *AuthHandler) RedirectToKeycloak(c *gin.Context) {
	stateID, err := utils.GenerateRandomBase64Str()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if err = a.authStore.SetState(c, stateID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	c.Redirect(http.StatusFound, a.authClient.Oauth.AuthCodeURL(stateID))
}

func (a *AuthHandler) RenderLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.tmpl", gin.H{
		"Title":       "Welcome",
		"Message":     "Please log in to continue",
		"KeycloakURL": fmt.Sprintf("http://%s/auth/login-keycloak", a.serverAddr),
	})
}
