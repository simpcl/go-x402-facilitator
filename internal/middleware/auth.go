package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/x402/go-x402-facilitator/internal/config"
	"github.com/x402/go-x402-facilitator/pkg/types"
)

// AuthMiddleware provides authentication middleware
func AuthMiddleware(authConfig config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for health endpoints
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
			c.Next()
			return
		}

		// Check API key in Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, types.ErrorResponse{
				Error:   "missing_authorization",
				Message: "Authorization header is required",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		// Extract API key from "Bearer <key>" format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, types.ErrorResponse{
				Error:   "invalid_authorization_format",
				Message: "Authorization header must be in format 'Bearer <api_key>'",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		apiKey := parts[1]

		// Validate API key
		if !isValidAPIKey(apiKey, authConfig.APIKeys) {
			c.JSON(http.StatusUnauthorized, types.ErrorResponse{
				Error:   "invalid_api_key",
				Message: "Invalid or expired API key",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		// Store API key in context for potential use
		c.Set("api_key", apiKey)
		c.Next()
	}
}

// isValidAPIKey checks if the provided API key is valid
func isValidAPIKey(apiKey string, validKeys []string) bool {
	for _, validKey := range validKeys {
		if apiKey == validKey {
			return true
		}
	}
	return false
}