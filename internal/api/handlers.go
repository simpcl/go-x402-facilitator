package api

import (
	"fmt"
	"net/http"

	"go-x402-facilitator/internal/facilitator"
	"go-x402-facilitator/pkg/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// Handler contains the API handlers
type Handler struct {
	facilitator *facilitator.Facilitator
}

// NewHandler creates a new API handler
func NewHandler(f *facilitator.Facilitator) *Handler {
	return &Handler{
		facilitator: f,
	}
}

// RegisterRoutes registers all API routes
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	api := router.Group("/facilitator")
	{
		api.POST("/verify", h.Verify)
		api.POST("/settle", h.Settle)
		api.GET("/supported", h.GetSupported)
	}

	// Health check endpoint
	router.GET("/health", h.Health)
	router.GET("/ready", h.Ready)
}

// Verify handles the /facilitator/verify endpoint
func (h *Handler) Verify(c *gin.Context) {
	var req types.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Invalid request body for verify")
		c.JSON(http.StatusBadRequest, types.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body: " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate request
	if err := h.validateVerifyRequest(&req); err != nil {
		log.Error().Err(err).Msg("Validation failed for verify request")
		c.JSON(http.StatusBadRequest, types.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Call facilitator
	response, err := h.facilitator.Verify(c.Request.Context(), &req)
	if err != nil {
		log.Error().Err(err).Msg("Facilitator verify failed")
		c.JSON(http.StatusInternalServerError, types.ErrorResponse{
			Error:   "internal_error",
			Message: "Internal server error during verification",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Settle handles the /facilitator/settle endpoint
func (h *Handler) Settle(c *gin.Context) {
	var req types.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Invalid request body for settle")
		c.JSON(http.StatusBadRequest, types.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body: " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate request
	if err := h.validateVerifyRequest(&req); err != nil {
		log.Error().Err(err).Msg("Validation failed for settle request")
		c.JSON(http.StatusBadRequest, types.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Call facilitator
	response, err := h.facilitator.Settle(c.Request.Context(), &req)
	if err != nil {
		log.Error().Err(err).Msg("Facilitator settle failed")
		c.JSON(http.StatusInternalServerError, types.ErrorResponse{
			Error:   "internal_error",
			Message: "Internal server error during settlement",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetSupported handles the /facilitator/supported endpoint
func (h *Handler) GetSupported(c *gin.Context) {
	response := h.facilitator.GetSupported()
	c.JSON(http.StatusOK, response)
}

// Health handles the /health endpoint
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

// Ready handles the /ready endpoint
func (h *Handler) Ready(c *gin.Context) {
	// Check if facilitator is initialized
	if h.facilitator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"reason": "facilitator_not_initialized",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
	})
}

// validateVerifyRequest validates the verify/settle request
func (h *Handler) validateVerifyRequest(req *types.VerifyRequest) error {
	// Check if network is supported
	if !h.facilitator.IsNetworkSupported(req.PaymentRequirements.Network) {
		return fmt.Errorf("unsupported network: %s", req.PaymentRequirements.Network)
	}

	// Basic field validation
	if req.PaymentPayload.X402Version == 0 {
		return fmt.Errorf("missing x402 version")
	}

	if req.PaymentPayload.Scheme == "" {
		return fmt.Errorf("missing scheme")
	}

	if req.PaymentPayload.Network == "" {
		return fmt.Errorf("missing network")
	}

	if req.PaymentRequirements.Scheme == "" {
		return fmt.Errorf("missing payment requirements scheme")
	}

	if req.PaymentRequirements.Network == "" {
		return fmt.Errorf("missing payment requirements network")
	}

	if req.PaymentRequirements.MaxAmountRequired == "" {
		return fmt.Errorf("missing max amount required")
	}

	if req.PaymentRequirements.Resource == "" {
		return fmt.Errorf("missing resource")
	}

	if req.PaymentRequirements.PayTo == "" {
		return fmt.Errorf("missing pay to address")
	}

	if req.PaymentRequirements.Asset == "" {
		return fmt.Errorf("missing asset address")
	}

	// Check if scheme matches
	if req.PaymentPayload.Scheme != req.PaymentRequirements.Scheme {
		return fmt.Errorf("scheme mismatch between payload and requirements")
	}

	// Check if network matches
	if req.PaymentPayload.Network != req.PaymentRequirements.Network {
		return fmt.Errorf("network mismatch between payload and requirements")
	}

	return nil
}
