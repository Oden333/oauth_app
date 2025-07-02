package server

import (
	"context"
	"net/http"
	"oauth_app/internal/config"
	authCtrl "oauth_app/internal/handler/auth"
	"oauth_app/internal/handler/render"
	"oauth_app/internal/middleware"
	"oauth_app/pkg/keycloak"
	"time"

	store "oauth_app/internal/store/redis"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	serverAddr string
	config     *config.Config

	router     *gin.Engine
	httpServer *http.Server // Добавляем http.Server для управления shutdown

	authHandler   *authCtrl.AuthHandler
	renderHandler *render.RenderHandler
}

func NewServer(ctx context.Context,
	serverAddr string,
	cfg *config.Config,
	authClient *keycloak.Client,
	redisClient *redis.Client,
) *Server {
	router := gin.Default()
	// Load HTML templates
	router.LoadHTMLGlob("../internal/templates/*.tmpl")

	authStore := store.NewAuthRedisManager(redisClient)
	sessionStore := store.NewSessionRedisManager(redisClient)

	authHandler := authCtrl.New(cfg, serverAddr, authClient, authStore, sessionStore)

	server := &Server{
		serverAddr:  serverAddr,
		router:      router,
		config:      cfg,
		authHandler: authHandler,
	}

	server.httpServer = &http.Server{
		Addr:    serverAddr,
		Handler: router,
	}

	authMiddleware := middleware.NewAuthMiddleware(
		ctx,
		authClient,
		sessionStore,
	)

	server.setupRoutes(authMiddleware)
	return server
}

func (s *Server) setupRoutes(authMiddleware *middleware.AuthMiddleware) {
	// Health check
	// s.router.GET("/health", s.healthCheck)

	// login page
	s.router.GET("/", s.authHandler.RenderLoginPage)
	auth := s.router.Group("/auth")
	{
		auth.GET("/login", s.authHandler.RenderLoginPage)
		auth.GET("/login-keycloak", s.authHandler.RedirectToKeycloak)
		auth.GET("/callback", s.authHandler.CallbackHandler)
	}

	// Protected routes group
	protected := s.router.Group("/")
	protected.Use(authMiddleware.RequireAuth())
	{
		protected.GET("/success-login", s.renderHandler.SuccessLogin)
		protected.GET("/dashboard", s.renderHandler.Dashboard)

	}
}

func (s *Server) Run() error {
	// Используем http.Server вместо router.Run()
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	// Создаем новый контекст с таймаутом для shutdown, если переданный контекст не имеет таймаута
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	return s.httpServer.Shutdown(ctx)
}
