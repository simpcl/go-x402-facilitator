package state

import (
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"go-x402-facilitator/models"
)

// FacilitatorState tracks the state of each facilitator
type FacilitatorState struct {
	LastTxHash     *string      `json:"lastTxHash"`
	LastAmount     *string      `json:"lastAmount"`
	LastTo         *string      `json:"lastTo"`
	LastAt         *time.Time   `json:"lastAt"`
	SuccessCount   int          `json:"successCount"`
	FailureCount   int          `json:"failureCount"`
	TotalVolume    float64      `json:"totalVolume"`
	TotalGasNative float64      `json:"totalGasNative"`
	mutex          sync.RWMutex `json:"-"`
}

// SettlementState manages global settlement state
type SettlementState struct {
	Alpha  FacilitatorState `json:"alpha"`
	Beta   FacilitatorState `json:"beta"`
	Gamma  FacilitatorState `json:"gamma"`
	Settle FacilitatorState `json:"settle"`
	Totals Totals           `json:"totals"`
	mutex  sync.RWMutex     `json:"-"`
}

// Totals tracks global statistics
type Totals struct {
	TotalRequests  int     `json:"totalRequests"`
	TotalVolume    float64 `json:"totalVolume"`
	TotalGasNative float64 `json:"totalGasNative"`
}

var globalState = &SettlementState{
	Alpha: FacilitatorState{
		LastTxHash:     nil,
		LastAmount:     nil,
		LastTo:         nil,
		LastAt:         nil,
		SuccessCount:   0,
		FailureCount:   0,
		TotalVolume:    0.0,
		TotalGasNative: 0.0,
	},
	Beta: FacilitatorState{
		LastTxHash:     nil,
		LastAmount:     nil,
		LastTo:         nil,
		LastAt:         nil,
		SuccessCount:   0,
		FailureCount:   0,
		TotalVolume:    0.0,
		TotalGasNative: 0.0,
	},
	Gamma: FacilitatorState{
		LastTxHash:     nil,
		LastAmount:     nil,
		LastTo:         nil,
		LastAt:         nil,
		SuccessCount:   0,
		FailureCount:   0,
		TotalVolume:    0.0,
		TotalGasNative: 0.0,
	},
	Settle: FacilitatorState{
		LastTxHash:     nil,
		LastAmount:     nil,
		LastTo:         nil,
		LastAt:         nil,
		SuccessCount:   0,
		FailureCount:   0,
		TotalVolume:    0.0,
		TotalGasNative: 0.0,
	},
	Totals: Totals{
		TotalRequests:  0,
		TotalVolume:    0.0,
		TotalGasNative: 0.0,
	},
}

// GetSettlementState returns the current settlement state
func GetSettlementState() *SettlementState {
	globalState.mutex.RLock()
	defer globalState.mutex.RUnlock()

	// Return a copy to avoid concurrent access issues
	stateCopy := *globalState
	return &stateCopy
}

// UpdateSettlement updates the settlement state for a facilitator
func UpdateSettlement(facilitatorName string, settlement *models.Settlement) {
	globalState.mutex.Lock()
	defer globalState.mutex.Unlock()

	var facilitator *FacilitatorState
	switch facilitatorName {
	case "alpha":
		facilitator = &globalState.Alpha
	case "beta":
		facilitator = &globalState.Beta
	case "gamma":
		facilitator = &globalState.Gamma
	case "settle":
		facilitator = &globalState.Settle
	default:
		return
	}

	facilitator.mutex.Lock()
	defer facilitator.mutex.Unlock()

	// Update facilitator state
	facilitator.LastTxHash = &settlement.TxHash
	facilitator.LastAmount = &settlement.Amount
	facilitator.LastTo = &settlement.To
	now := time.Now()
	facilitator.LastAt = &now
	facilitator.SuccessCount++

	// Parse amount to float64 for volume calculation
	if amountFloat, err := parseAmountToFloat64(settlement.Amount); err == nil {
		facilitator.TotalVolume += amountFloat
		globalState.Totals.TotalVolume += amountFloat
	}

	// Parse gas cost to float64
	if gasCostFloat, err := parseGasCostToFloat64(settlement.GasCost); err == nil {
		facilitator.TotalGasNative += gasCostFloat
		globalState.Totals.TotalGasNative += gasCostFloat
	}

	globalState.Totals.TotalRequests++
}

// IncrementFailure increments the failure count for a facilitator
func IncrementFailure(facilitatorName string) {
	globalState.mutex.Lock()
	defer globalState.mutex.Unlock()

	var facilitator *FacilitatorState
	switch facilitatorName {
	case "alpha":
		facilitator = &globalState.Alpha
	case "beta":
		facilitator = &globalState.Beta
	case "gamma":
		facilitator = &globalState.Gamma
	case "settle":
		facilitator = &globalState.Settle
	default:
		return
	}

	facilitator.mutex.Lock()
	defer facilitator.mutex.Unlock()

	facilitator.FailureCount++
	globalState.Totals.TotalRequests++
}

// GetFacilitatorState returns the state of a specific facilitator
func GetFacilitatorState(facilitatorName string) *FacilitatorState {
	globalState.mutex.RLock()
	defer globalState.mutex.RUnlock()

	var facilitator *FacilitatorState
	switch facilitatorName {
	case "alpha":
		facilitator = &globalState.Alpha
	case "beta":
		facilitator = &globalState.Beta
	case "gamma":
		facilitator = &globalState.Gamma
	default:
		return nil
	}

	facilitator.mutex.RLock()
	defer facilitator.mutex.RUnlock()

	// Return a copy
	stateCopy := *facilitator
	return &stateCopy
}

// IsFacilitatorActive checks if a facilitator has processed any transactions
func IsFacilitatorActive(facilitatorName string) bool {
	state := GetFacilitatorState(facilitatorName)
	return state != nil && state.LastTxHash != nil
}

// GetEvents returns recent transaction events
func GetEvents(explorerURL string) []models.TransactionEvent {
	globalState.mutex.RLock()
	defer globalState.mutex.RUnlock()

	var events []models.TransactionEvent

	// Add Alpha event if exists
	if globalState.Alpha.LastTxHash != nil && globalState.Alpha.LastAt != nil {
		event := models.TransactionEvent{
			Time:        globalState.Alpha.LastAt.Format("15:04:05"),
			Facilitator: "Alpha",
			Amount:      getStringOrEmpty(globalState.Alpha.LastAmount) + " tokens",
			Route:       "/api/secret",
			Merchant:    getShortAddress(getStringOrEmpty(globalState.Alpha.LastTo)),
			TxHashShort: getShortTxHash(*globalState.Alpha.LastTxHash),
		}
		if explorerURL != "" {
			event.ExplorerUrl = explorerURL + "/tx/" + *globalState.Alpha.LastTxHash
		}
		events = append(events, event)
	}

	// Add Beta event if exists
	if globalState.Beta.LastTxHash != nil && globalState.Beta.LastAt != nil {
		event := models.TransactionEvent{
			Time:        globalState.Beta.LastAt.Format("15:04:05"),
			Facilitator: "Beta",
			Amount:      getStringOrEmpty(globalState.Beta.LastAmount) + " tokens",
			Route:       "/api/secret",
			Merchant:    getShortAddress(getStringOrEmpty(globalState.Beta.LastTo)),
			TxHashShort: getShortTxHash(*globalState.Beta.LastTxHash),
		}
		if explorerURL != "" {
			event.ExplorerUrl = explorerURL + "/tx/" + *globalState.Beta.LastTxHash
		}
		events = append(events, event)
	}

	// Add Gamma event if exists
	if globalState.Gamma.LastTxHash != nil && globalState.Gamma.LastAt != nil {
		event := models.TransactionEvent{
			Time:        globalState.Gamma.LastAt.Format("15:04:05"),
			Facilitator: "Gamma",
			Amount:      getStringOrEmpty(globalState.Gamma.LastAmount) + " tokens",
			Route:       "/api/secret",
			Merchant:    getShortAddress(getStringOrEmpty(globalState.Gamma.LastTo)),
			TxHashShort: getShortTxHash(*globalState.Gamma.LastTxHash),
		}
		if explorerURL != "" {
			event.ExplorerUrl = explorerURL + "/tx/" + *globalState.Gamma.LastTxHash
		}
		events = append(events, event)
	}

	return events
}

// Helper functions

func parseAmountToFloat64(amount string) (float64, error) {
	// Remove potential token symbols and spaces
	cleanAmount := amount
	if len(amount) > 6 && amount[len(amount)-6:] == "tokens" {
		cleanAmount = amount[:len(amount)-7]
		cleanAmount = strings.TrimSpace(cleanAmount)
	}

	// Convert to float64
	var result float64
	_, err := fmt.Sscanf(cleanAmount, "%f", &result)
	return result, err
}

func parseGasCostToFloat64(gasCost string) (float64, error) {
	// Parse gas cost as a big number then convert to float64
	gasCostBig, ok := new(big.Float).SetString(gasCost)
	if !ok {
		return 0.0, fmt.Errorf("invalid gas cost format")
	}
	result, _ := gasCostBig.Float64()
	return result, nil
}

func getStringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getShortAddress(address string) string {
	if len(address) < 10 {
		return address
	}
	return address[:6] + "..." + address[len(address)-4:]
}

func getShortTxHash(txHash string) string {
	if len(txHash) < 10 {
		return txHash
	}
	return txHash[:6] + "..." + txHash[len(txHash)-4:]
}
