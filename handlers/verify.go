package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"go-x402-facilitator/models"
	"go-x402-facilitator/services"
)

// VerifyHandler handles payment verification operations
type VerifyHandler struct {
	verifyService *services.VerifyService
}

// NewVerifyHandler creates a new verification handler
func NewVerifyHandler(rpcURL string) *VerifyHandler {
	return &VerifyHandler{
		verifyService: services.NewVerifyService(rpcURL),
	}
}

// VerifyPayment handles POST /api/verify requests
func (h *VerifyHandler) VerifyPayment(c *gin.Context) {
	var req models.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Log the verification request (for debugging)
	if gin.Mode() == gin.DebugMode {
		c.JSON(http.StatusOK, gin.H{
			"message": "Verification request received",
			"txHash": req.TxHash,
			"debug": true,
		})
		return
	}

	// Perform verification
	result, err := h.verifyService.VerifyPayment(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Verification failed",
			"details": err.Error(),
		})
		return
	}

	// Return verification result
	c.JSON(http.StatusOK, result)
}

// VerifyPaymentSimple handles GET /api/verify/{txHash} for simple verification
func (h *VerifyHandler) VerifyPaymentSimple(c *gin.Context) {
	txHash := c.Param("txHash")
	if txHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Transaction hash is required",
		})
		return
	}

	result, err := h.verifyService.VerifyPaymentSimple(txHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Verification failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetTransactionStatus handles GET /api/verify/{txHash}/status
func (h *VerifyHandler) GetTransactionStatus(c *gin.Context) {
	txHash := c.Param("txHash")
	if txHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Transaction hash is required",
		})
		return
	}

	success, blockNumber, err := h.verifyService.GetTransactionStatus(txHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get transaction status",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"txHash": txHash,
		"success": success,
		"blockNumber": blockNumber,
		"status": mapStatusToString(success),
	})
}

// GetTokenBalance handles GET /api/verify/balance/{tokenAddress}/{userAddress}
func (h *VerifyHandler) GetTokenBalance(c *gin.Context) {
	tokenAddress := c.Param("tokenAddress")
	userAddress := c.Param("userAddress")

	if tokenAddress == "" || userAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Token address and user address are required",
		})
		return
	}

	balance, err := h.verifyService.CheckTokenBalance(tokenAddress, userAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check token balance",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tokenAddress": tokenAddress,
		"userAddress": userAddress,
		"balance": balance.String(),
	})
}

// GetChainInfo handles GET /api/verify/chain-info
func (h *VerifyHandler) GetChainInfo(c *gin.Context) {
	chainID, err := h.verifyService.GetChainID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get chain info",
			"details": err.Error(),
		})
		return
	}

	gasPrice, err := h.verifyService.EstimateGasPrice()
	if err != nil {
		gasPrice = "unknown"
	}

	c.JSON(http.StatusOK, gin.H{
		"chainId": chainID,
		"chainName": mapChainIDToName(chainID),
		"gasPrice": gasPrice,
		"rpcUrl": h.verifyService.RPCURL,
	})
}

// ValidateAddress handles POST /api/validate-address
func (h *VerifyHandler) ValidateAddress(c *gin.Context) {
	var req struct {
		Address string `json:"address"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	isValid := h.verifyService.ValidateAddress(req.Address)
	c.JSON(http.StatusOK, gin.H{
		"address": req.Address,
		"valid": isValid,
	})
}

// Helper functions

func mapStatusToString(success bool) string {
	if success {
		return "success"
	}
	return "failed"
}

func mapChainIDToName(chainID int64) string {
	switch chainID {
	case 1:
		return "Ethereum Mainnet"
	case 56:
		return "BNB Smart Chain Mainnet"
	case 97:
		return "BNB Smart Chain Testnet"
	case 137:
		return "Polygon Mainnet"
	case 80001:
		return "Mumbai Testnet"
	case 42161:
		return "Arbitrum One"
	case 421613:
		return "Arbitrum Goerli"
	case 10:
		return "Optimism"
	case 69:
		return "Optimism Kovan"
	default:
		return "Unknown Chain"
	}
}