package facilitator

import (
	"context"
	"fmt"
	"sync"

	"github.com/x402/go-x402-facilitator/internal/config"
	facilitatorTypes "github.com/x402/go-x402-facilitator/pkg/types"
)

// Facilitator is the main facilitator service
type Facilitator struct {
	config     *config.Config
	evmClients map[string]*EVMFacilitator
	mu         sync.RWMutex
}

// New creates a new facilitator instance
func New(cfg *config.Config) (*Facilitator, error) {
	f := &Facilitator{
		config:     cfg,
		evmClients: make(map[string]*EVMFacilitator),
	}

	// Initialize EVM clients for supported networks
	if err := f.initEVMClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize EVM clients: %w", err)
	}

	return f, nil
}

// initEVMClients initializes EVM clients for all supported networks
func (f *Facilitator) initEVMClients() error {
	supportedNetworks := f.config.GetSupportedNetworks()

	if len(supportedNetworks) == 0 {
		// Create EVM facilitator for this network
		evmFacilitator, err := NewEVMFacilitator(
			f.config.Facilitator.DefaultChainRPC,
			f.config.Facilitator.DefaultChainID,
			f.config.Facilitator.DefaultTokenAddress,
			f.config.Facilitator.PrivateKey,
		)
		if err != nil {
			return fmt.Errorf("failed to create EVM facilitator for network %s: %w", f.config.Facilitator.DefaultChainNetwork, err)
		}

		f.evmClients[f.config.Facilitator.DefaultChainNetwork] = evmFacilitator
		return nil
	}

	for _, network := range supportedNetworks {
		// Get RPC URL for the network
		rpcURL, err := f.config.GetChainRPC(network)
		if err != nil {
			return fmt.Errorf("failed to get RPC URL for network %s: %w", network, err)
		}

		// Get chain ID for the network
		chainID, err := f.config.GetChainID(network)
		if err != nil {
			return fmt.Errorf("failed to get chain ID for network %s: %w", network, err)
		}

		// Get token contract address for the network
		tokenAddress, err := f.config.GetTokenAddress(network)
		if err != nil {
			return fmt.Errorf("failed to get token contract address for network %s: %w", network, err)
		}

		// Create EVM facilitator for this network
		evmFacilitator, err := NewEVMFacilitator(
			rpcURL,
			chainID,
			tokenAddress,
			f.config.Facilitator.PrivateKey,
		)
		if err != nil {
			return fmt.Errorf("failed to create EVM facilitator for network %s: %w", network, err)
		}

		f.evmClients[network] = evmFacilitator
	}

	return nil
}

// Verify verifies a payment payload
func (f *Facilitator) Verify(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.VerifyResponse, error) {
	// Validate scheme
	if err := f.validateScheme(req.PaymentRequirements.Scheme); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Payer:         "",
		}, nil
	}

	// Validate network
	if err := f.validateNetwork(req.PaymentRequirements.Network); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "invalid_network",
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
	// Validate scheme
	if err := f.validateScheme(req.PaymentRequirements.Scheme); err != nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "unsupported_scheme",
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

	for _, network := range f.config.GetSupportedNetworks() {
		for _, scheme := range f.config.GetSupportedSchemes() {
			kinds = append(kinds, facilitatorTypes.SupportedKind{
				X402Version: 1,
				Scheme:      scheme,
				Network:     network,
			})
		}
	}

	return &facilitatorTypes.SupportedResponse{
		X402Version: 1,
		Kinds:       kinds,
	}
}

// DiscoverResources returns discovered resources (placeholder implementation)
func (f *Facilitator) DiscoverResources(ctx context.Context, resourceType string, limit, offset int) (*facilitatorTypes.DiscoveryResponse, error) {
	// This is a placeholder implementation
	// In a production environment, this would query a database or external service
	// for available x402-enabled resources

	items := []facilitatorTypes.DiscoveryItem{
		{
			Resource:    "https://api.example.com/premium-data",
			Type:        "http",
			X402Version: 1,
			Accepts: []facilitatorTypes.PaymentRequirements{
				{
					Scheme:            "exact",
					Network:           "base-sepolia",
					MaxAmountRequired: "10000",
					Resource:          "https://api.example.com/premium-data",
					Description:       "Access to premium market data",
					MimeType:          "application/json",
					PayTo:             "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
					MaxTimeoutSeconds: 60,
					Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
					Extra: map[string]interface{}{
						"name":    "GenericToken",
						"version": "1",
					},
				},
			},
			LastUpdated: 1703123456,
		},
	}

	// Apply pagination
	start := offset
	if start > len(items) {
		start = len(items)
	}

	end := start + limit
	if end > len(items) {
		end = len(items)
	}

	var paginatedItems []facilitatorTypes.DiscoveryItem
	if start < len(items) {
		paginatedItems = items[start:end]
	}

	return &facilitatorTypes.DiscoveryResponse{
		X402Version: 1,
		Items:       paginatedItems,
	}, nil
}

func (f *Facilitator) validateScheme(scheme string) error {
	if len(f.config.Supported.Schemes) > 0 {
		for _, supported := range f.config.Supported.Schemes {
			if supported == scheme {
				return nil
			}
		}
	}
	return fmt.Errorf("unsupported scheme: %s", scheme)
}

func (f *Facilitator) validateNetwork(network string) error {
	if len(f.config.Supported.Networks) > 0 {
		for _, supported := range f.config.Supported.Networks {
			if supported == network {
				return nil
			}
		}
	}
	return fmt.Errorf("unsupported network: %s", network)
}

// verifyExact handles exact scheme verification
func (f *Facilitator) verifyExact(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.VerifyResponse, error) {
	f.mu.RLock()
	evmClient, exists := f.evmClients[req.PaymentRequirements.Network]
	f.mu.RUnlock()

	if !exists {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_network",
			Payer:         "",
		}, nil
	}

	return evmClient.Verify(ctx, &req.PaymentPayload, &req.PaymentRequirements)
}

// settleExact handles exact scheme settlement
func (f *Facilitator) settleExact(ctx context.Context, req *facilitatorTypes.VerifyRequest) (*facilitatorTypes.SettleResponse, error) {
	f.mu.RLock()
	evmClient, exists := f.evmClients[req.PaymentRequirements.Network]
	f.mu.RUnlock()

	if !exists {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "unsupported_network",
			Transaction: "",
			Network:     req.PaymentPayload.Network,
			Payer:       "",
		}, nil
	}

	return evmClient.Settle(ctx, &req.PaymentPayload, &req.PaymentRequirements)
}

// Close closes all client connections
func (f *Facilitator) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var lastErr error
	for network, client := range f.evmClients {
		// Close client connection if it provides a Close method
		if closer, ok := interface{}(client).(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				lastErr = fmt.Errorf("failed to close client for network %s: %w", network, err)
			}
		}
	}

	return lastErr
}

// GetClientCount returns the number of initialized clients
func (f *Facilitator) GetClientCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.evmClients)
}

// IsNetworkSupported checks if a network is supported
func (f *Facilitator) IsNetworkSupported(network string) bool {
	f.mu.RLock()
	_, exists := f.evmClients[network]
	f.mu.RUnlock()
	return exists
}
