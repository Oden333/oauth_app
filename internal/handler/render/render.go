package render

import (
	"encoding/json"
	"net/http"
	"oauth_app/internal/config"
	"oauth_app/internal/store"

	"github.com/gin-gonic/gin"
)

type RenderHandler struct {
	cfg *config.Config
}

func New(
	cfg *config.Config,
) *RenderHandler {
	return &RenderHandler{
		cfg: cfg,
	}
}

func (r *RenderHandler) SuccessLogin(c *gin.Context) {
	// / Get user info from context (set by middleware)
	userID, _ := c.Get("user_id")
	userEmail, _ := c.Get("user_email")
	c.HTML(http.StatusOK, "success.tmpl", gin.H{
		"Title":        "Login Successful",
		"Message":      "You have successfully logged in!",
		"Username":     userID,
		"Email":        userEmail,
		"DashboardURL": "/dashboard",
		"LogoutURL":    "/logout",
	})
}

func (r *RenderHandler) Dashboard(c *gin.Context) {
	// Get session data with safe type assertion
	rawSession, exists := c.Get("user_session")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No session found"})
		return
	}
	// Perform type assertion with error checking
	sessionData, ok := rawSession.(*store.SessionData)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid session data type"})
		return
	}
	data, err := json.MarshalIndent(sessionData, " ", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	// Now you can safely use the properly typed sessionData
	c.HTML(http.StatusOK, "dashboard.tmpl", gin.H{
		"username": sessionData.UserInfoData.FullName,
		"email":    sessionData.UserInfoData.Email,
		"data":     string(data),
	})
}
