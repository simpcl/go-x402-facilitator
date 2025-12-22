package facilitator

import (
	"context"
	"fmt"
	"sync"

	"go-x402-facilitator/internal/facilitator"
	"go-x402-facilitator/pkg/types"
)

// PaymentFacilitator is the public interface for X402 payment facilitation
type PaymentFacilitator interface {
	// Verify verifies a payment payload
	Verify(ctx context.Context, req *types.VerifyRequest) (*types.VerifyResponse, error)

	// Settle settles a payment
	Settle(ctx context.Context, req *types.VerifyRequest) (*types.SettleResponse, error)

	// GetSupported returns the supported schemes and networks
	GetSupported() *types.SupportedResponse

	// IsNetworkSupported checks if a network is supported
	IsNetworkSupported(network string) bool

	// Close closes all client connections
	Close() error
}

// New creates a new payment facilitator instance
// This is the main entry point for using the facilitator as a library
// Supports multiple blockchain networks
func New(cfg *FacilitatorConfig) (PaymentFacilitator, error) {
	wrapper := &facilitatorWrapper{
		evmFacilitators: make(map[string]*facilitator.EVMFacilitator),
		networks:        make(map[string]NetworkConfig),
		supportedScheme: cfg.SupportedScheme,
		mu:              sync.RWMutex{},
	}

	// If no networks configured, return error
	if len(cfg.Networks) == 0 {
		return nil, fmt.Errorf("at least one network must be configured")
	}

	// Create an EVM facilitator for each configured network
	for networkName, networkCfg := range cfg.Networks {
		// Create EVM facilitator for this network
		evmFacilitator, err := facilitator.NewEVMFacilitator(
			networkCfg.ChainRPC,
			networkCfg.ChainID,
			networkCfg.TokenAddress,
			cfg.PrivateKey,
		)
		if err != nil {
			// Close already created facilitators on error
			wrapper.Close()
			return nil, fmt.Errorf("failed to create EVM facilitator for network %s: %w", networkName, err)
		}

		wrapper.evmFacilitators[networkName] = evmFacilitator
		wrapper.networks[networkName] = networkCfg
	}

	return wrapper, nil
}

// FacilitatorConfig is the public configuration for the facilitator
// Supports multiple blockchain networks
type FacilitatorConfig struct {
	// Networks configuration - map of network name to network config
	Networks map[string]NetworkConfig

	// Shared configuration across all networks
	PrivateKey      string // Private key used for all networks
	SupportedScheme string // Supported payment scheme (e.g., "exact")
}

// NetworkConfig represents configuration for a single blockchain network
type NetworkConfig struct {
	ChainRPC      string
	ChainID       uint64
	TokenAddress  string
	TokenName     string
	TokenVersion  string
	TokenDecimals int64
	GasLimit      uint64
	GasPrice      string
}

// facilitatorWrapper wraps multiple EVM facilitators to implement the public interface
type facilitatorWrapper struct {
	evmFacilitators map[string]*facilitator.EVMFacilitator
	networks        map[string]NetworkConfig
	supportedScheme string
	mu              sync.RWMutex
}

func (w *facilitatorWrapper) Verify(ctx context.Context, req *types.VerifyRequest) (*types.VerifyResponse, error) {
	// Validate scheme
	if err := w.validateScheme(req.PaymentRequirements.Scheme); err != nil {
		return &types.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Payer:         "",
		}, nil
	}

	// Validate network
	network := req.PaymentRequirements.Network
	w.mu.RLock()
	evmFacilitator, exists := w.evmFacilitators[network]
	w.mu.RUnlock()

	if !exists {
		return &types.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_network",
			Payer:         "",
		}, nil
	}

	// Route to appropriate handler based on scheme
	switch req.PaymentRequirements.Scheme {
	case "exact":
		return evmFacilitator.Verify(ctx, &req.PaymentPayload, &req.PaymentRequirements)
	default:
		return &types.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Payer:         "",
		}, nil
	}
}

func (w *facilitatorWrapper) Settle(ctx context.Context, req *types.VerifyRequest) (*types.SettleResponse, error) {
	// Validate scheme
	if err := w.validateScheme(req.PaymentRequirements.Scheme); err != nil {
		return &types.SettleResponse{
			Success:     false,
			ErrorReason: "unsupported_scheme",
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}

	// Validate network
	network := req.PaymentRequirements.Network
	w.mu.RLock()
	evmFacilitator, exists := w.evmFacilitators[network]
	w.mu.RUnlock()

	if !exists {
		return &types.SettleResponse{
			Success:     false,
			ErrorReason: "unsupported_network",
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}

	// Route to appropriate handler based on scheme
	switch req.PaymentRequirements.Scheme {
	case "exact":
		return evmFacilitator.Settle(ctx, &req.PaymentPayload, &req.PaymentRequirements)
	default:
		return &types.SettleResponse{
			Success:     false,
			ErrorReason: "unsupported_scheme",
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}
}

func (w *facilitatorWrapper) GetSupported() *types.SupportedResponse {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var kinds []types.SupportedKind

	// Build response with all networks
	for networkName := range w.evmFacilitators {
		kinds = append(kinds, types.SupportedKind{
			X402Version: 1,
			Scheme:      w.supportedScheme,
			Network:     networkName,
		})
	}

	return &types.SupportedResponse{
		X402Version: 1,
		Kinds:       kinds,
	}
}

func (w *facilitatorWrapper) IsNetworkSupported(network string) bool {
	w.mu.RLock()
	_, exists := w.evmFacilitators[network]
	w.mu.RUnlock()
	return exists
}

func (w *facilitatorWrapper) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var lastErr error
	for networkName, evmFacilitator := range w.evmFacilitators {
		if evmFacilitator != nil {
			if err := evmFacilitator.Close(); err != nil {
				lastErr = fmt.Errorf("failed to close EVM facilitator for network %s: %w", networkName, err)
			}
		}
	}

	return lastErr
}

func (w *facilitatorWrapper) validateScheme(scheme string) error {
	if scheme != w.supportedScheme {
		return fmt.Errorf("unsupported scheme: %s (only %s is supported)", scheme, w.supportedScheme)
	}
	return nil
}
