package facilitator

import (
	"context"

	"go-x402-facilitator/internal/config"
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
func New(cfg *FacilitatorConfig) (PaymentFacilitator, error) {
	// Convert public config to internal config
	internalCfg := &config.Config{
		Facilitator: config.FacilitatorConfig{
			DefaultChainNetwork:  cfg.DefaultChainNetwork,
			DefaultChainRPC:      cfg.DefaultChainRPC,
			DefaultChainID:       cfg.DefaultChainID,
			DefaultTokenAddress:  cfg.DefaultTokenAddress,
			DefaultTokenName:     cfg.DefaultTokenName,
			DefaultTokenVersion:  cfg.DefaultTokenVersion,
			DefaultTokenDecimals: cfg.DefaultTokenDecimals,
			PrivateKey:           cfg.PrivateKey,
			GasLimit:             cfg.GasLimit,
			GasPrice:             cfg.GasPrice,
		},
		Supported: config.SupportedConfig{
			Schemes:        cfg.SupportedSchemes,
			Networks:       cfg.SupportedNetworks,
			ChainIds:       cfg.ChainIds,
			ChainRPCs:      cfg.ChainRPCs,
			TokenContracts: cfg.TokenContracts,
		},
	}

	// Create internal facilitator
	f, err := facilitator.New(internalCfg)
	if err != nil {
		return nil, err
	}

	return &facilitatorWrapper{facilitator: f}, nil
}

// FacilitatorConfig is the public configuration for the facilitator
type FacilitatorConfig struct {
	// Default chain configuration
	DefaultChainNetwork  string
	DefaultChainRPC      string
	DefaultChainID       uint64
	DefaultTokenAddress  string
	DefaultTokenName     string
	DefaultTokenVersion  string
	DefaultTokenDecimals int64
	PrivateKey           string
	GasLimit             uint64
	GasPrice             string

	// Supported networks and schemes
	SupportedSchemes  []string
	SupportedNetworks []string
	ChainIds          map[string]uint64
	ChainRPCs         map[string]string
	TokenContracts    map[string]string
}

// facilitatorWrapper wraps the internal facilitator to implement the public interface
type facilitatorWrapper struct {
	facilitator *facilitator.Facilitator
}

func (w *facilitatorWrapper) Verify(ctx context.Context, req *types.VerifyRequest) (*types.VerifyResponse, error) {
	return w.facilitator.Verify(ctx, req)
}

func (w *facilitatorWrapper) Settle(ctx context.Context, req *types.VerifyRequest) (*types.SettleResponse, error) {
	return w.facilitator.Settle(ctx, req)
}

func (w *facilitatorWrapper) GetSupported() *types.SupportedResponse {
	return w.facilitator.GetSupported()
}

func (w *facilitatorWrapper) IsNetworkSupported(network string) bool {
	return w.facilitator.IsNetworkSupported(network)
}

func (w *facilitatorWrapper) Close() error {
	return w.facilitator.Close()
}
