package utils

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func CallTokenContractFunction(
	ctx context.Context,
	client *ethclient.Client,
	abiFunctionString string,
	tokenContractAddress common.Address,
	functionName string,
	args ...interface{},
) ([]interface{}, error) {
	parsedABI, err := abi.JSON(strings.NewReader(abiFunctionString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI %s: %w", abiFunctionString, err)
	}

	// Use bind.Call for proper ABI encoding/decoding
	callOpts := &bind.CallOpts{
		Pending: false,
		Context: ctx,
	}

	boundContract := bind.NewBoundContract(tokenContractAddress, parsedABI, client, client, client)
	var results []interface{}
	err = boundContract.Call(callOpts, &results, functionName, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to call %s with args %v: %w", functionName, args, err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no results returned for function %s with args %v", functionName, args)
	}

	return results, nil
}

func FetchTokenInfoWithContext(
	ctx context.Context,
	client *ethclient.Client,
	tokenContractAddress common.Address,
) (string, string, error) {
	tokenName, err := FetchTokenNameWithContext(ctx, client, tokenContractAddress)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch token name: %w", err)
	}
	tokenVersion, err := FetchTokenVersionWithContext(ctx, client, tokenContractAddress)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch token version: %w", err)
	}
	return tokenName, tokenVersion, nil
}

func FetchTokenNameWithContext(
	ctx context.Context,
	client *ethclient.Client,
	tokenContractAddress common.Address,
) (string, error) {
	// ERC20 Token name() function ABI
	nameABI := `[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"}]`

	// Get token name
	nameResults, err := CallTokenContractFunction(ctx, client, nameABI, tokenContractAddress, "name")
	if err != nil {
		return "", fmt.Errorf("failed to call name(): %w", err)
	}
	tokenName, ok := nameResults[0].(string)
	if !ok {
		return "", fmt.Errorf("name() returned invalid type")
	}
	return tokenName, nil
}

func FetchTokenVersionWithContext(
	ctx context.Context,
	client *ethclient.Client,
	tokenContractAddress common.Address,
) (string, error) {
	// ERC20 Token version() function ABI
	versionABI := `[{"constant":true,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"type":"function"}]`

	// Get token version
	versionResults, err := CallTokenContractFunction(ctx, client, versionABI, tokenContractAddress, "version")
	if err != nil {
		return "", fmt.Errorf("failed to call version(): %w", err)
	}
	tokenVersion, ok := versionResults[0].(string)
	if !ok {
		return "", fmt.Errorf("version() returned invalid type")
	}

	return tokenVersion, nil
}

func GetTokenBalanceWithContext(
	ctx context.Context,
	client *ethclient.Client,
	tokenContractAddress common.Address,
	ownerAddress common.Address,
) (*big.Int, error) {
	// Test connection with a simple call
	_, err := client.ChainID(ctx)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("client connection failed: %w", err)
	}

	// ERC20 balanceOf function ABI
	balanceABI := `[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]`

	results, err := CallTokenContractFunction(ctx, client, balanceABI, tokenContractAddress, "balanceOf", ownerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to call balanceOf: %w", err)
	}

	balance, ok := results[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid balance type returned")
	}

	return balance, nil
}

// GetDomainSeparatorWithContext fetches the actual domain separator from the contract
func GetDomainSeparatorWithContext(
	ctx context.Context,
	client *ethclient.Client,
	tokenContractAddress common.Address,
) ([]byte, error) {
	// DOMAIN_SEPARATOR() function ABI
	domainABI := `[{"constant":true,"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"name":"","type":"bytes32"}],"type":"function"}]`

	results, err := CallTokenContractFunction(ctx, client, domainABI, tokenContractAddress, "DOMAIN_SEPARATOR")
	if err != nil {
		return nil, fmt.Errorf("failed to call DOMAIN_SEPARATOR: %w", err)
	}

	domainBytes, ok := results[0].([32]byte)
	if !ok {
		// Try as common.Hash
		if hash, ok := results[0].(common.Hash); ok {
			return hash.Bytes(), nil
		}
		return nil, fmt.Errorf("DOMAIN_SEPARATOR returned invalid type")
	}

	return domainBytes[:], nil
}

func PackTransferWithAuthorization(
	from string,
	to string,
	valueStr string,
	validAfterStr string,
	validBeforeStr string,
	nonceStr string,
	V *big.Int,
	R *big.Int,
	S *big.Int,
) ([]byte, error) {
	fromAddr := common.HexToAddress(from)
	toAddr := common.HexToAddress(to)
	value, ok := new(big.Int).SetString(valueStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid value: %s", valueStr)
	}
	validAfter, ok := new(big.Int).SetString(validAfterStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid validAfter: %s", validAfterStr)
	}
	validBefore, ok := new(big.Int).SetString(validBeforeStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid validBefore: %s", validBeforeStr)
	}
	nonce := common.HexToHash(nonceStr)

	// Extract v, r, s values
	// var v uint8
	if V == nil || R == nil || S == nil {
		return nil, fmt.Errorf("invalid v, r, s values")
	}
	var v uint8 = 0
	v = uint8(V.Uint64())

	// Normalize v value: if it's 0 or 1, add 27 to get 27 or 28
	// If it's already 27 or 28, keep it as is
	if v == 0 || v == 1 {
		v += 27
	}
	// Ensure v is 27 or 28
	if v != 27 && v != 28 {
		return nil, fmt.Errorf("invalid v value: %d (must be 27 or 28)", v)
	}

	// Convert *big.Int to [32]byte for ABI compatibility
	var rBytes [32]byte
	var sBytes [32]byte

	rBytes = common.BigToHash(R)
	sBytes = common.BigToHash(S)

	// Generic token contract ABI (transferWithAuthorization function)
	tokenABIString := `[{
		"name": "transferWithAuthorization",
		"type": "function",
		"stateMutability": "nonpayable",
		"inputs": [
			{"name": "from", "type": "address"},
			{"name": "to", "type": "address"},
			{"name": "value", "type": "uint256"},
			{"name": "validAfter", "type": "uint256"},
			{"name": "validBefore", "type": "uint256"},
			{"name": "nonce", "type": "bytes32"},
			{"name": "v", "type": "uint8"},
			{"name": "r", "type": "bytes32"},
			{"name": "s", "type": "bytes32"}
		],
		"outputs": []
	}]`

	tokenABI, err := abi.JSON(strings.NewReader(tokenABIString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token ABI: %w", err)
	}

	// Pack the function call data with correct types
	return tokenABI.Pack(
		"transferWithAuthorization",
		fromAddr,
		toAddr,
		value,
		validAfter,
		validBefore,
		nonce,
		v,
		rBytes,
		sBytes,
	)
}
