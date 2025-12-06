package utils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	eip712 "github.com/x402/go-x402-facilitator/pkg/eip712full"
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

// RecoverAddress recovers the signing address from EIP-712 typed data
func RecoverAddress(typedData *eip712.TypedData, signatureHex string) (common.Address, error) {
	signature, err := hexutil.Decode(signatureHex)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to decode signatureHex: %s", signatureHex)
		return common.Address{}, err
	}

	typedDataHashBytes, err := HashTypedDataBytes(typedData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash typedData")
		return common.Address{}, err
	}

	recoveredAddr, err := crypto.SigToPub(typedDataHashBytes, signature)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sig to pub")
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*recoveredAddr), nil
}

func BuildTypedData(
	from string,
	to string,
	value string,
	validAfter string,
	validBefore string,
	nonce string,
	verifyingContract string,
	chainID uint64,
	tokenName string,
	tokenVersion string,
) *eip712.TypedData {
	// Ensure addresses are lowercase for EIP-712 hash consistency
	// The client signs with lowercase addresses, so we must match that format
	fromLower := strings.ToLower(from)
	toLower := strings.ToLower(to)

	typedData := &eip712.TypedData{
		Types: map[string][]eip712.TypedDataField{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": {
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: eip712.TypedDataDomain{
			Name:              tokenName,
			Version:           tokenVersion,
			ChainId:           chainID,
			VerifyingContract: common.HexToAddress(verifyingContract),
		},
		Message: map[string]interface{}{
			"from":        fromLower, // Contract uses address type, so maybe this is not a string, but an address
			"to":          toLower,   // Contract uses address type, so maybe this is not a string, but an address
			"value":       value,
			"validAfter":  validAfter,
			"validBefore": validBefore,
			"nonce":       nonce,
		},
	}
	// Log transaction parameters for debugging
	log.Info().
		Str("from", fromLower).
		Str("to", toLower).
		Str("value", value).
		Str("validAfter", validAfter).
		Str("validBefore", validBefore).
		Str("nonce", nonce).
		Str("verifyingContract", verifyingContract).
		Uint64("chainID", chainID).
		Str("tokenName", tokenName).
		Str("tokenVersion", tokenVersion).
		Msg("Build TypedData for transferWithAuthorization")
	return typedData
}

func GenerateTypedDataSignature(typedData *eip712.TypedData, privateKey *ecdsa.PrivateKey) (string, error) {
	if typedData == nil {
		return "", fmt.Errorf("typedData is nil")
	}
	if privateKey == nil {
		return "", fmt.Errorf("privateKey is nil")
	}

	// Generate hash
	typedDataHashBytes, err := HashTypedDataBytes(typedData)
	if err != nil {
		return "", fmt.Errorf("Failed to hash: %w", err)
	}

	// Sign the hash
	signature, err := crypto.Sign(typedDataHashBytes, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// Convert to hex string
	return hexutil.Encode(signature), nil
}

// HashTypedData creates the hash of EIP-712 typed data
func HashTypedData(typedData *eip712.TypedData) (common.Hash, error) {
	digest, err := typedData.HashStruct()
	if err != nil {
		return common.Hash{}, err
	}

	domainSeparator, err := typedData.HashDomain()
	if err != nil {
		return common.Hash{}, err
	}

	// EIP-712 Standard: keccak256("\x19\x01" || domainSeparator || structHash)
	return crypto.Keccak256Hash(
		append(append([]byte("\x19\x01"), domainSeparator...), digest...),
		// append([]byte{0x19, 0x01}, append(domainSeparator[:], typeHash[:]...)...),
	), nil
}

func HashTypedDataBytes(typedData *eip712.TypedData) ([]byte, error) {
	fullHash, err := HashTypedData(typedData)
	if err != nil {
		return nil, err
	}
	return fullHash.Bytes(), nil
}

func HashTypedDataBytesByEthAccount(typedData *eip712.TypedData) ([]byte, error) {
	digest, err := typedData.HashStruct()
	if err != nil {
		return nil, err
	}

	domainSeparator, err := typedData.HashDomain()
	if err != nil {
		return nil, err
	}

	fullHash := accounts.TextHash(append(
		append([]byte("\x19\x01"), domainSeparator...),
		digest...,
	))
	return fullHash, nil
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

	// Add buffer for expiration check (3 blocks, assuming 2 seconds per block)
	expirationBuffer := int64(6)

	// Add buffer for validAfter check to account for:
	// 1. System time vs block timestamp differences
	// 2. Network latency between verification and settlement
	// 3. Block time variations
	// Allow validAfter to be up to 10 seconds in the future
	validAfterBuffer := int64(10)

	if vb < now+expirationBuffer {
		return false, "authorization_expired"
	}

	// Allow validAfter to be slightly in the future to account for time differences
	if va > now+validAfterBuffer {
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
