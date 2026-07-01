package main

import (
	"log"

	"github.com/consultprompts/auth-service/database"
	"github.com/consultprompts/auth-service/internal/handler"
	"github.com/consultprompts/auth-service/internal/repository"
	"github.com/consultprompts/auth-service/internal/service"
	"github.com/consultprompts/auth-service/pkg/jwt"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, using existing environment variables")
	}

	pool := database.Connect()
	defer pool.Close()

	privateKey, err := jwt.LoadPrivateKey("jwt_private.pem")
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	roleRepo := repository.NewRoleRepository(pool)
	authService := service.NewAuthService(userRepo, tokenRepo, roleRepo, privateKey)
	authHandler := handler.NewAuthHandler(authService)

	router := gin.Default()

	router.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	router.POST("/auth/register", authHandler.Register)
	router.POST("/auth/login", authHandler.Login)
	router.POST("/auth/refresh", authHandler.Refresh)
	router.GET("/auth/logout", authHandler.Logout)

	router.Run(":8080")
}
