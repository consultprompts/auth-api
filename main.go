package main

import (
	"log/slog"
	"os"

	"github.com/consultprompts/auth-service/database"
	"github.com/consultprompts/auth-service/internal/email"
	"github.com/consultprompts/auth-service/internal/handler"
	"github.com/consultprompts/auth-service/internal/middleware"
	"github.com/consultprompts/auth-service/internal/repository"
	"github.com/consultprompts/auth-service/internal/service"
	"github.com/consultprompts/auth-service/pkg/jwt"
	"github.com/consultprompts/auth-service/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	logger.Init()

	if err := godotenv.Load(); err != nil {
		slog.Warn("no .env file found, using existing environment variables")
	}

	pool := database.Connect()
	defer pool.Close()

	privateKey, err := jwt.LoadPrivateKey("jwt_private.pem")
	if err != nil {
		slog.Error("failed to load private key", "error", err)
		os.Exit(1)
	}

	publicKey, err := jwt.LoadPublicKey("jwt_public.pem")
	if err != nil {
		slog.Error("failed to load public key", "error", err)
		os.Exit(1)
	}

	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	roleRepo := repository.NewRoleRepository(pool)
	emailClient := email.NewEmailClient()
	loginProtection := middleware.NewLoginProtection()
	authService := service.NewAuthService(userRepo, tokenRepo, roleRepo, emailClient, privateKey)
	authHandler := handler.NewAuthHandler(authService, publicKey, pool)

	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(middleware.RequestLogger(), middleware.Recovery())

	router.POST("/auth/register", authHandler.Register)
	router.POST("/auth/login", loginProtection.Middleware(), authHandler.Login)
	router.POST("/auth/refresh", authHandler.Refresh)
	router.POST("/auth/logout", authHandler.Logout)
	router.GET("/.well-known/jwks.json", authHandler.JWKS)
	router.POST("/auth/verify-email", authHandler.VerifyEmail)
	router.POST("/auth/password/reset-request", authHandler.RequestPasswordReset)
	router.POST("/auth/password/reset", authHandler.ResetPassword)
	router.GET("/healthz", authHandler.Healthz)

	protected := router.Group("/")
	protected.Use(middleware.RequireAuth(publicKey))
	{
		protected.GET("/auth/me", authHandler.Me)
		protected.POST("/auth/roles/assign", authHandler.AssignRole)
		protected.POST("/auth/roles/remove", authHandler.RemoveRole)
	}

	slog.Info("Starting server", "addr", ":8080")
	if err := router.Run(":8080"); err != nil {
		slog.Error("Server stopped", "error", err)
		os.Exit(1)
	}
}
