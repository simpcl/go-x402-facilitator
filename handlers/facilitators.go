package handlers

import (
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"

	"go-x402-facilitator/config"
	"go-x402-facilitator/models"
	"go-x402-facilitator/services"
)

// FacilitatorHandler handles facilitator API endpoints
type FacilitatorHandler struct {
	service *services.FacilitatorService
	config  *config.Config
}

// NewFacilitatorHandler creates a new facilitator handler
func NewFacilitatorHandler(service *services.FacilitatorService, cfg *config.Config) *FacilitatorHandler {
	return &FacilitatorHandler{
		service: service,
		config:  cfg,
	}
}

// HandleAlpha handles Alpha facilitator requests
func (h *FacilitatorHandler) HandleAlpha(c *gin.Context) {
	h.handleFacilitator(c, "alpha")
}

// HandleBeta handles Beta facilitator requests
func (h *FacilitatorHandler) HandleBeta(c *gin.Context) {
	h.handleFacilitator(c, "beta")
}

// HandleGamma handles Gamma facilitator requests
func (h *FacilitatorHandler) HandleGamma(c *gin.Context) {
	h.handleFacilitator(c, "gamma")
}

// handleFacilitator is the common handler for all facilitators
func (h *FacilitatorHandler) handleFacilitator(c *gin.Context, facilitatorName string) {
	var req models.PaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	response, err := h.service.ProcessPayment(facilitatorName, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Settlement failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// HandleTransfer handles generic ERC20 token transfer
func (h *FacilitatorHandler) HandleTransfer(c *gin.Context) {
	var req models.ContractInteraction
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	response, err := h.service.TransferERC20(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetFacilitatorAddresses returns facilitator addresses for the secret endpoint
func (h *FacilitatorHandler) GetFacilitatorAddresses() (alpha, beta, gamma string) {
	alpha = ""
	beta = ""
	gamma = ""

	if h.config.AlphaPrivateKey != "" {
		if privateKey, err := crypto.HexToECDSA(h.config.AlphaPrivateKey); err == nil {
			alpha = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
		}
	}

	if h.config.BetaPrivateKey != "" {
		if privateKey, err := crypto.HexToECDSA(h.config.BetaPrivateKey); err == nil {
			beta = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
		}
	}

	if h.config.GammaPrivateKey != "" {
		if privateKey, err := crypto.HexToECDSA(h.config.GammaPrivateKey); err == nil {
			gamma = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
		}
	}

	return
}