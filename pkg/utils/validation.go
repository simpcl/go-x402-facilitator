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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/x402/go-x402-facilitator/pkg/types"
)

// SupportedEVMNetworks lists all supported EVM networks
var SupportedEVMNetworks = []string{
	"localhost",
}

// SupportedChains maps network names to chain IDs
var SupportedChains = map[string]int64{
	"localhost": 1337,
}

// USDCContractAddresses maps network names to USDC contract addresses
var USDCContractAddresses = map[string]string{
	"localhost": "0xC35898F0f03C0894107869844d7467Af417aD868",
}

// ParseSignature parses an Ethereum signature
func ParseSignature(signatureHex string) (*types.Signature, error) {
	signature, err := hexutil.Decode(signatureHex)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes long: %d", len(signature))
	}

	R := new(big.Int).SetBytes(signature[:32])
	S := new(big.Int).SetBytes(signature[32:64])
	V := new(big.Int).SetBytes([]byte{signature[64]})

	v := V.Uint64()
	if v == 0 || v == 1 {
		v = v + 27
	}
	if v != 27 && v != 28 {
		return nil, fmt.Errorf("invalid v value: %d", v)
	}

	return &types.Signature{
		V: V,
		R: R,
		S: S,
	}, nil
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
