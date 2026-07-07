package main

import (
	"log/slog"
	"os"

	database "github.com/consultprompts/auth-service/database"
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
		slog.Warn("No .env file found, using existing environment variables")
	}

	database.RunMigrations()

	pool := database.Connect()
	defer pool.Close()

	privateKey, err := jwt.LoadPrivateKey("jwt_private.pem")
	if err != nil {
		slog.Error("Failed to load private key", "error", err)
		os.Exit(1)
	}

	publicKey, err := jwt.LoadPublicKey("jwt_public.pem")
	if err != nil {
		slog.Error("Failed to load public key", "error", err)
		os.Exit(1)
	}

	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	roleRepo := repository.NewRoleRepository(pool)
	var emailClient service.EmailClient
	if ec := email.NewEmailClient(); ec != nil {
		emailClient = ec
	}
	loginProtection := middleware.NewLoginProtection()
	authService := service.NewAuthService(userRepo, tokenRepo, roleRepo, emailClient, privateKey)
	authHandler := handler.NewAuthHandler(authService, publicKey, pool)

	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.SetTrustedProxies(nil)
	router.Use(middleware.RequestLogger(), middleware.Recovery())

	router.POST("/auth/register", authHandler.Register)
	router.POST("/auth/login", loginProtection.Middleware(), authHandler.Login)
	router.POST("/auth/refresh", authHandler.Refresh)
	router.POST("/auth/logout", authHandler.Logout)
	router.GET("/.well-known/jwks.json", authHandler.JWKS)
	router.POST("/auth/verify-email", authHandler.VerifyEmail)
	router.POST("/auth/verify-email/resend", authHandler.ResendVerification)
	router.POST("/auth/password/reset-request", authHandler.RequestPasswordReset)
	router.POST("/auth/password/reset", authHandler.ResetPassword)
	router.GET("/auth/google/login", authHandler.GoogleLogin)
	router.GET("/auth/google/callback", authHandler.GoogleCallback)
	router.GET("/healthz", authHandler.Healthz)

	admin := router.Group("/")
	admin.Use(middleware.RequireAuth(publicKey))
	admin.Use(middleware.RequireRole("admin"))
	{
		admin.GET("/auth/users/:id", authHandler.GetUser)
		admin.POST("/auth/roles/assign", authHandler.AssignRole)
		admin.POST("/auth/roles/remove", authHandler.RemoveRole)
	}

	protected := router.Group("/")
	protected.Use(middleware.RequireAuth(publicKey))
	{
		protected.GET("/auth/me", authHandler.Me)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	slog.Info("Starting server", "addr", port)
	if err := router.Run(":" + port); err != nil {
		slog.Error("Server stopped", "error", err)
		os.Exit(1)
	}
}
