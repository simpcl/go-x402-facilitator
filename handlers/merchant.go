package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"go-x402-facilitator/models"
	"go-x402-facilitator/state"
)

// MerchantHandler handles merchant-related endpoints
type MerchantHandler struct {
	facilitatorHandler *FacilitatorHandler
}

// NewMerchantHandler creates a new merchant handler
func NewMerchantHandler(fh *FacilitatorHandler) *MerchantHandler {
	return &MerchantHandler{
		facilitatorHandler: fh,
	}
}

// HandleSecret handles the protected secret endpoint
func (h *MerchantHandler) HandleSecret(c *gin.Context) {
	paidProof := c.GetHeader("x-paid-proof")

	// If no payment proof, return 402 with facilitator list
	if paidProof == "" {
		alphaAddr, betaAddr, gammaAddr, settleAddr := h.facilitatorHandler.GetFacilitatorAddresses()

		response := models.PaymentRequiredResponse{
			Price: "1 USDx",
			Asset: "0xcfFA309a5Fb3ac7419eBC8Ba4a6063Ff2a7585F5",
			Facilitators: []models.Facilitator{
				{
					Name:     "Alpha",
					Fee:      "0.5%",
					Endpoint: "/api/facilitators/alpha",
					Address:  alphaAddr,
					Live:     true,
				},
				{
					Name:     "Beta",
					Fee:      "1.0%",
					Endpoint: "/api/facilitators/beta",
					Address:  betaAddr,
					Live:     false,
				},
				{
					Name:     "Gamma",
					Fee:      "2.0%",
					Endpoint: "/api/facilitators/gamma",
					Address:  gammaAddr,
					Live:     false,
				},
				{
					Name:     "Settle",
					Fee:      "0%",
					Endpoint: "/api/facilitators/settle",
					Address:  settleAddr,
					Live:     true,
					Note:     "Coinbase x402 compatible zero-fee facilitator",
				},
			},
		}

		c.JSON(http.StatusPaymentRequired, response)
		return
	}

	// If payment proof exists, return the protected data
	c.JSON(http.StatusOK, gin.H{
		"alpha": "whale 0x9b... moved 320,000 USDx to CEX 4 min ago",
	})
}

// HandleStats handles the statistics endpoint
func (h *MerchantHandler) HandleStats(c *gin.Context) {
	settlementState := state.GetSettlementState()

	alphaActive := settlementState.Alpha.LastTxHash != nil
	betaActive := settlementState.Beta.LastTxHash != nil
	gammaActive := settlementState.Gamma.LastTxHash != nil
	settleActive := settlementState.Settle.LastTxHash != nil

	activeFacilitators := 0
	if alphaActive {
		activeFacilitators++
	}
	if betaActive {
		activeFacilitators++
	}
	if gammaActive {
		activeFacilitators++
	}
	if settleActive {
		activeFacilitators++
	}

	// Calculate Alpha uptime
	totalAlphaRequests := settlementState.Alpha.SuccessCount + settlementState.Alpha.FailureCount
	alphaUptime := "0%"
	if totalAlphaRequests > 0 {
		uptimePercentage := float64(settlementState.Alpha.SuccessCount) / float64(totalAlphaRequests) * 100
		alphaUptime = strconv.FormatFloat(uptimePercentage, 'f', 1, 64) + "%"
	}

	totalRequests := settlementState.Totals.TotalRequests
	totalVolume := strconv.FormatFloat(settlementState.Totals.TotalVolume, 'f', 2, 64) + " USDx"
	gasSponsored := strconv.FormatFloat(settlementState.Totals.TotalGasBNB, 'f', 6, 64) + " BNB"

	summary := models.SummaryStats{
		ActiveFacilitators: activeFacilitators,
		Requests24h:       totalRequests,
		Volume24h:         totalVolume,
		AvgFee:            "0.7%",
		Uptime:            alphaUptime,
		AvgSettlementTime: func() string {
			if alphaActive {
				return "< 2s"
			}
			return "N/A"
		}(),
		MerchantRevenue: totalVolume,
		MerchantAddress: "0x183052a3526d2ebd0f8dd7a90bed2943e0126795", // Default merchant address
		GasSponsored24h:  gasSponsored,
	}

	// Build facilitator stats
	facilitators := []models.FacilitatorStats{
		{
			Name:        "Facilitator Alpha",
			Status:      func() string { if alphaActive { return "LIVE" } else { return "OFFLINE" } }(),
			StatusTone:  func() string { if alphaActive { return "good" } else { return "warn" } }(),
			Fee:         "0.5%",
			Requests:    strconv.Itoa(settlementState.Alpha.SuccessCount),
			Volume:      strconv.Itoa(settlementState.Alpha.SuccessCount) + ".00 USDx",
			LastTxHash:  func() string {
				if settlementState.Alpha.LastTxHash != nil {
					txHash := *settlementState.Alpha.LastTxHash
					if len(txHash) > 10 {
						return txHash[:6] + "..." + txHash[len(txHash)-4:]
					}
					return txHash
				}
				return "No tx yet"
			}(),
			BscScanUrl: func() string {
				if settlementState.Alpha.LastTxHash != nil {
					return "https://testnet.bscscan.com/tx/" + *settlementState.Alpha.LastTxHash
				}
				return ""
			}(),
			Tags: func() []string {
				if alphaActive {
					return []string{"Pays gas for user", "Auto-settlement <2s"}
				}
				return []string{"Offline"}
			}(),
			Uptime: alphaUptime,
		},
		{
			Name:        "Facilitator Beta",
			Status:      func() string { if betaActive { return "LIVE" } else { return "OFFLINE" } }(),
			StatusTone:  func() string { if betaActive { return "good" } else { return "warn" } }(),
			Fee:         "1.0%",
			Requests:    strconv.Itoa(settlementState.Beta.SuccessCount),
			Volume:      strconv.Itoa(settlementState.Beta.SuccessCount) + ".00 USDx",
			LastTxHash:  func() string {
				if settlementState.Beta.LastTxHash != nil {
					txHash := *settlementState.Beta.LastTxHash
					if len(txHash) > 10 {
						return txHash[:6] + "..." + txHash[len(txHash)-4:]
					}
					return txHash
				}
				return "No tx yet"
			}(),
			BscScanUrl: func() string {
				if settlementState.Beta.LastTxHash != nil {
					return "https://testnet.bscscan.com/tx/" + *settlementState.Beta.LastTxHash
				}
				return ""
			}(),
			Tags: func() []string {
				if betaActive {
					return []string{"Pays gas for user"}
				}
				return []string{"Offline"}
			}(),
			Uptime: "0%",
		},
		{
			Name:        "Facilitator Gamma",
			Status:      func() string { if gammaActive { return "LIVE" } else { return "OFFLINE" } }(),
			StatusTone:  func() string { if gammaActive { return "good" } else { return "warn" } }(),
			Fee:         "2.0%",
			Requests:    strconv.Itoa(settlementState.Gamma.SuccessCount),
			Volume:      strconv.Itoa(settlementState.Gamma.SuccessCount) + ".00 USDx",
			LastTxHash:  func() string {
				if settlementState.Gamma.LastTxHash != nil {
					txHash := *settlementState.Gamma.LastTxHash
					if len(txHash) > 10 {
						return txHash[:6] + "..." + txHash[len(txHash)-4:]
					}
					return txHash
				}
				return "No tx yet"
			}(),
			BscScanUrl: func() string {
				if settlementState.Gamma.LastTxHash != nil {
					return "https://testnet.bscscan.com/tx/" + *settlementState.Gamma.LastTxHash
				}
				return ""
			}(),
			Tags: func() []string {
				if gammaActive {
					return []string{"Fast priority", "2.0% fee"}
				}
				return []string{"Offline"}
			}(),
			Uptime: "0%",
		},
		{
			Name:        "Facilitator Settle",
			Status:      func() string { if settleActive { return "LIVE" } else { return "OFFLINE" } }(),
			StatusTone:  func() string { if settleActive { return "good" } else { return "warn" } }(),
			Fee:         "0%",
			Requests:    strconv.Itoa(settlementState.Settle.SuccessCount),
			Volume:      strconv.Itoa(settlementState.Settle.SuccessCount) + ".00 USDx",
			LastTxHash:  func() string {
				if settlementState.Settle.LastTxHash != nil {
					txHash := *settlementState.Settle.LastTxHash
					if len(txHash) > 10 {
						return txHash[:6] + "..." + txHash[len(txHash)-4:]
					}
					return txHash
				}
				return "No tx yet"
			}(),
			BscScanUrl: func() string {
				if settlementState.Settle.LastTxHash != nil {
					return "https://testnet.bscscan.com/tx/" + *settlementState.Settle.LastTxHash
				}
				return ""
			}(),
			Tags: func() []string {
				if settleActive {
					return []string{"Zero fee", "Coinbase x402 compatible", "Pays gas for user"}
				}
				return []string{"Offline"}
			}(),
			Uptime: "0%",
		},
	}

	// Get events
	events := state.GetEvents()

	response := models.StatsResponse{
		Summary:      summary,
		Facilitators: facilitators,
		Events:       events,
	}

	c.JSON(http.StatusOK, response)
}