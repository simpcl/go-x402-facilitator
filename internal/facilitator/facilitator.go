package facilitator

import (
	"context"
	"errors"
	"fmt"

	"github.com/agent-guide/go-x402-facilitator/internal/config"
	facilitatorTypes "github.com/agent-guide/go-x402-facilitator/pkg/types"

	"github.com/rs/zerolog/log"
)

// Facilitator is the main facilitator service
type Facilitator struct {
	config         *config.FacilitatorConfig
	evmFacilitator *EVMFacilitator
}

// New creates a new facilitator instance
func New(cfg *config.FacilitatorConfig) (*Facilitator, error) {
	// Create EVM facilitator for the configured network
	evmFacilitator, err := NewEVMFacilitator(
		cfg.ChainRPC,
		cfg.ChainID,
		cfg.TokenAddress,
		cfg.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM facilitator for network %s: %w", cfg.Network, err)
	}

	f := &Facilitator{
		config:         cfg,
		evmFacilitator: evmFacilitator,
	}
	return f, nil
}

// Verify verifies a payment payload
func (f *Facilitator) Verify(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.VerifyResponse, error) {
	// Validate request
	if err := f.validateVerifyRequest(req); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: err.Error(),
			Payer:         "",
		}, nil
	}

	// Route to appropriate handler based on scheme and network
	switch req.PaymentRequirements.Scheme {
	case "exact":
		return f.verifyExact(ctx, req)
	default:
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Payer:         "",
		}, nil
	}
}

// Settle settles a payment
func (f *Facilitator) Settle(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.SettleResponse, error) {
	// Validate request
	if err := f.validateVerifyRequest(req); err != nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: err.Error(),
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}

	// Route to appropriate handler based on scheme and network
	switch req.PaymentRequirements.Scheme {
	case "exact":
		return f.settleExact(ctx, req)
	default:
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "unsupported_scheme",
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}
}

// GetSupported returns the supported schemes and networks
func (f *Facilitator) GetSupported() *facilitatorTypes.SupportedResponse {
	var kinds []facilitatorTypes.SupportedKind

	kinds = append(kinds, facilitatorTypes.SupportedKind{
		X402Version: 1,
		Scheme:      f.config.SupportedScheme,
		Network:     f.config.Network,
	})

	return &facilitatorTypes.SupportedResponse{
		X402Version: 1,
		Kinds:       kinds,
	}
}

func (f *Facilitator) validateVerifyRequest(req *facilitatorTypes.VerifyRequest) error {
	if req.PaymentRequirements.Scheme != f.config.SupportedScheme {
		log.Error().Msgf("unsupported scheme: %s (only %s is supported)", req.PaymentRequirements.Scheme, f.config.SupportedScheme)
		return errors.New("unsupported_scheme")
	}
	if req.PaymentRequirements.Network != f.config.Network {
		log.Error().Msgf("unsupported network: %s (only %s is supported)", req.PaymentRequirements.Network, f.config.Network)
		return errors.New("unsupported_network")
	}
	return nil
}

// verifyExact handles exact scheme verification
func (f *Facilitator) verifyExact(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.VerifyResponse, error) {
	if f.evmFacilitator == nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "facilitator_not_initialized",
			Payer:         "",
		}, nil
	}

	return f.evmFacilitator.Verify(ctx, &req.PaymentPayload, &req.PaymentRequirements)
}

// settleExact handles exact scheme settlement
func (f *Facilitator) settleExact(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.SettleResponse, error) {
	if f.evmFacilitator == nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "facilitator_not_initialized",
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}

	return f.evmFacilitator.Settle(ctx, &req.PaymentPayload, &req.PaymentRequirements)
}

// Close closes the EVM facilitator connection
func (f *Facilitator) Close() error {
	if f.evmFacilitator != nil {
		return f.evmFacilitator.Close()
	}
	return nil
}

// IsNetworkSupported checks if a network is supported
func (f *Facilitator) IsNetworkSupported(network string) bool {
	return network == f.config.Network
}
