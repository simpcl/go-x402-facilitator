package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"

	"go-x402-facilitator/config"
	"go-x402-facilitator/handlers"
	"go-x402-facilitator/services"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize facilitator service
	facilitatorService, err := services.NewFacilitatorService(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize facilitator service: %v", err)
	}

	// Initialize handlers
	facilitatorHandler := handlers.NewFacilitatorHandler(facilitatorService, cfg)
	merchantHandler := handlers.NewMerchantHandler(facilitatorHandler)

	// Initialize Gin router
	router := gin.Default()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.Next()
	})

	// Setup routes
	setupRoutes(router, facilitatorHandler, merchantHandler)

	// Start server
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("Starting server on %s", addr)
	log.Printf("API endpoints:")
	log.Printf("  POST /api/facilitators/alpha - Alpha facilitator (0.5% fee)")
	log.Printf("  POST /api/facilitators/beta  - Beta facilitator (1.0% fee)")
	log.Printf("  POST /api/facilitators/gamma - Gamma facilitator (2.0% fee)")
	log.Printf("  POST /api/transfer           - Generic ERC20 transfer")
	log.Printf("  GET  /api/secret             - Protected resource (402 payment)")
	log.Printf("  GET  /api/stats              - Settlement statistics")

	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func setupRoutes(router *gin.Engine, fh *handlers.FacilitatorHandler, mh *handlers.MerchantHandler) {
	api := router.Group("/api")

	// Facilitator endpoints
	api.POST("/facilitators/alpha", fh.HandleAlpha)
	api.POST("/facilitators/beta", fh.HandleBeta)
	api.POST("/facilitators/gamma", fh.HandleGamma)

	// Generic transfer endpoint
	api.POST("/transfer", fh.HandleTransfer)

	// Merchant endpoints
	api.GET("/secret", mh.HandleSecret)
	api.GET("/stats", mh.HandleStats)

	// Health check
	api.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
			"service": "go-x402-facilitator",
		})
	})

	// Root endpoint with API info
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"name": "Go x402 Facilitator",
			"description": "A Go implementation of x402 payment facilitators on BNB Chain",
			"version": "1.0.0",
			"endpoints": map[string]string{
				"facilitators": "/api/facilitators/{alpha|beta|gamma}",
				"transfer": "/api/transfer",
				"secret": "/api/secret",
				"stats": "/api/stats",
				"health": "/api/health",
			},
		})
	})
}