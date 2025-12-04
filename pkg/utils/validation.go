package utils

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// SupportedEVMNetworks lists all supported EVM networks
var SupportedEVMNetworks = []string{
	"localhost",
	"ethereum-sepolia",
	"ethereum",
	"base-sepolia",
	"base",
	"avalanche-fuji",
	"avalanche",
	"polygon",
	"polygon-mumbai",
}

// SupportedChains maps network names to chain IDs
var SupportedChains = map[string]int64{
	"localhost":        1337,
	"ethereum-sepolia": 11155111,
	"ethereum":         1,
	"base-sepolia":     84532,
	"base":             8453,
	"avalanche-fuji":   43113,
	"avalanche":        43114,
	"polygon":          137,
	"polygon-mumbai":   80001,
}

// USDCContractAddresses maps network names to USDC contract addresses
var USDCContractAddresses = map[string]string{
	"localhost":        "0xC35898F0f03C0894107869844d7467Af417aD868",
	"ethereum-sepolia": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
	"ethereum":         "0xA0b86a33E6417c5C2c0a9b0B7F8e0B7e8b4a0c8e",
	"base-sepolia":     "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
	"base":             "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531770b923",
	"avalanche-fuji":   "0x5425890298aedC1c239A4317bb48d42A35f0A3C4",
	"avalanche":        "0xB97EF9Ef8734C71904D8002F8b6Bc66Da9A84873",
	"polygon":          "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
	"polygon-mumbai":   "0xe6a84267191545774313146139d3d8395ca4b5d1",
}

// ValidateNetwork checks if the network is supported
func ValidateNetwork(network string) error {
	for _, supported := range SupportedEVMNetworks {
		if supported == network {
			return nil
		}
	}
	return fmt.Errorf("unsupported network: %s", network)
}

// ValidateScheme checks if the scheme is supported
func ValidateScheme(scheme string) error {
	if scheme != "exact" {
		return fmt.Errorf("unsupported scheme: %s", scheme)
	}
	return nil
}

// GetChainID returns the chain ID for the given network
func GetChainID(network string) (int64, error) {
	chainID, exists := SupportedChains[network]
	if !exists {
		return 0, fmt.Errorf("network %s not found", network)
	}
	return chainID, nil
}

// GetUSDCAddress returns the USDC contract address for the given network
func GetUSDCAddress(network string) (common.Address, error) {
	address, exists := USDCContractAddresses[network]
	if !exists {
		return common.Address{}, fmt.Errorf("USDC address for network %s not found", network)
	}
	return common.HexToAddress(address), nil
}

// CheckUSDCBalance checks the USDC balance of an address
func CheckUSDCBalance(client *ethclient.Client, network, address string) (*big.Int, error) {
	// Input validation
	if client == nil {
		return big.NewInt(0), fmt.Errorf("ethereum client is nil - blockchain connection not established")
	}

	if network == "" {
		return big.NewInt(0), fmt.Errorf("network cannot be empty")
	}

	if address == "" {
		return big.NewInt(0), fmt.Errorf("address cannot be empty")
	}

	// Validate address format
	if !common.IsHexAddress(address) {
		return big.NewInt(0), fmt.Errorf("invalid address format: %s", address)
	}

	usdcAddr, err := GetUSDCAddress(network)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("failed to get USDC address for network %s: %w", network, err)
	}

	addr := common.HexToAddress(address)

	// Check if client connection is actually working
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test connection with a simple call
	_, err = client.ChainID(ctx)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("ethereum client connection failed: %w", err)
	}

	// USDC contract ABI (only the balanceOf function)
	usdcABIJSON := `[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]`

	parsedABI, err := abi.JSON(strings.NewReader(usdcABIJSON))
	if err != nil {
		return big.NewInt(0), fmt.Errorf("failed to parse USDC ABI: %w", err)
	}

	// Create a callable contract with proper backend
	callOpts := &bind.CallOpts{
		Pending: false,
		Context: ctx,
	}

	// Use the ethclient as the backend
	boundContract := bind.NewBoundContract(usdcAddr, parsedABI, client, client, client)

	var results []interface{}
	err = boundContract.Call(callOpts, &results, "balanceOf", addr)
	if err != nil {
		// If contract call fails, return zero balance instead of panicking
		return big.NewInt(0), fmt.Errorf("failed to call USDC balanceOf: %w", err)
	}

	if len(results) == 0 {
		return big.NewInt(0), nil
	}

	balance, ok := results[0].(*big.Int)
	if !ok {
		return big.NewInt(0), fmt.Errorf("invalid balance type returned")
	}

	return balance, nil
}

// IsValidTimestamp checks if a timestamp is within the valid range
func IsValidTimestamp(validAfter, validBefore string) (bool, string) {
	now := time.Now().Unix()

	va, err := parseTimestamp(validAfter)
	if err != nil {
		return false, "invalid_valid_after_format"
	}

	vb, err := parseTimestamp(validBefore)
	if err != nil {
		return false, "invalid_valid_before_format"
	}

	// Add 3 blocks buffer (assuming 2 seconds per block)
	buffer := int64(6)

	if vb < now+buffer {
		return false, "authorization_expired"
	}

	if va > now {
		return false, "authorization_not_yet_valid"
	}

	return true, ""
}

// parseTimestamp parses a timestamp string to int64
func parseTimestamp(ts string) (int64, error) {
	var timestamp int64
	_, err := fmt.Sscanf(ts, "%d", &timestamp)
	return timestamp, err
}
