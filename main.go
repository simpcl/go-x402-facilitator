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
	verifyHandler := handlers.NewVerifyHandler(cfg.BNBTestnetRPC)

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
	setupRoutes(router, facilitatorHandler, merchantHandler, verifyHandler)

	// Start server
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("🚀 Starting Go x402 Facilitator Server on %s", addr)
	log.Printf("📡 Available API endpoints:")
	log.Printf("   POST /api/facilitators/alpha - Alpha facilitator (0.5% fee)")
	log.Printf("   POST /api/facilitators/beta  - Beta facilitator (1.0% fee)")
	log.Printf("   POST /api/facilitators/gamma - Gamma facilitator (2.0% fee)")
	log.Printf("   POST /api/transfer           - Generic ERC20 token transfer")
	log.Printf("   POST /api/verify             - Payment verification (Coinbase x402 compatible)")
	log.Printf("   GET  /api/verify/{txHash}    - Simple transaction verification")
	log.Printf("   GET  /api/secret             - Protected resource (returns 402 Payment Required)")
	log.Printf("   GET  /api/stats              - Settlement statistics and monitoring")
	log.Printf("   GET  /api/health             - Health check endpoint")
	log.Printf("   GET  /                       - API information")

	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func setupRoutes(router *gin.Engine, fh *handlers.FacilitatorHandler, mh *handlers.MerchantHandler, vh *handlers.VerifyHandler) {
	api := router.Group("/api")

	// Facilitator endpoints - identical to Facora1 functionality
	api.POST("/facilitators/alpha", fh.HandleAlpha)
	api.POST("/facilitators/beta", fh.HandleBeta)
	api.POST("/facilitators/gamma", fh.HandleGamma)

	// Generic ERC20 transfer endpoint - matches the image requirements
	api.POST("/transfer", fh.HandleTransfer)

	// Verification endpoints - Coinbase x402 compatible
	api.POST("/verify", vh.VerifyPayment)
	api.GET("/verify/:txHash", vh.VerifyPaymentSimple)
	api.GET("/verify/:txHash/status", vh.GetTransactionStatus)
	api.GET("/verify/balance/:tokenAddress/:userAddress", vh.GetTokenBalance)
	api.GET("/verify/chain-info", vh.GetChainInfo)

	// Address validation
	api.POST("/validate-address", vh.ValidateAddress)

	// Merchant endpoints - identical to Facora1 functionality
	api.GET("/secret", mh.HandleSecret)
	api.GET("/stats", mh.HandleStats)

	// Health check endpoint
	api.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "go-x402-facilitator",
			"network": "BNB Testnet",
		})
	})

	// Root endpoint with API information
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"name":        "Go x402 Facilitator",
			"description": "A Go implementation of x402 payment facilitators on BNB Chain",
			"version":     "1.0.0",
			"features": []string{
				"ERC20 token transfers with arbitrary contracts",
				"Gas limit customization",
				"EIP-2612 permit support (gasless payments)",
				"Multiple facilitators with different fee structures",
				"Real-time settlement tracking",
				"Payment verification (Coinbase x402 compatible)",
				"BNB Testnet integration",
			},
			"endpoints": map[string]string{
				"facilitators":       "/api/facilitators/{alpha|beta|gamma}",
				"erc20_transfer":     "/api/transfer",
				"verify_payment":     "/api/verify",
				"verify_tx":          "/api/verify/{txHash}",
				"verify_status":      "/api/verify/{txHash}/status",
				"verify_balance":     "/api/verify/balance/{tokenAddress}/{userAddress}",
				"verify_chain_info":  "/api/verify/chain-info",
				"validate_address":   "/api/validate-address",
				"protected_resource": "/api/secret",
				"statistics":         "/api/stats",
				"health":             "/api/health",
			},
		})
	})
}