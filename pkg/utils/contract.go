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

type TokenContractUtils struct {
	tokenAddress string
	client       *ethclient.Client
}

func NewTokenContractUtils(tokenAddress string, client *ethclient.Client) *TokenContractUtils {
	return &TokenContractUtils{
		tokenAddress: tokenAddress,
		client:       client,
	}
}

func (tcu *TokenContractUtils) FetchTokenInfo() (string, string, error) {
	return tcu.FetchTokenInfoWithContext(context.Background())
}

func (tcu *TokenContractUtils) FetchTokenInfoWithContext(ctx context.Context) (string, string, error) {
	tokenAddr := common.HexToAddress(tcu.tokenAddress)

	// ERC20 name() function ABI
	nameABI := `[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"}]`
	// GenericToken version() function ABI
	versionABI := `[{"constant":true,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"type":"function"}]`

	nameParsed, err := abi.JSON(strings.NewReader(nameABI))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse name ABI: %w", err)
	}

	versionParsed, err := abi.JSON(strings.NewReader(versionABI))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse version ABI: %w", err)
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		Context: ctx,
	}

	// Get token name
	nameContract := bind.NewBoundContract(tokenAddr, nameParsed, tcu.client, tcu.client, tcu.client)
	var nameResults []interface{}
	err = nameContract.Call(callOpts, &nameResults, "name")
	if err != nil {
		return "", "", fmt.Errorf("failed to call name(): %w", err)
	}
	if len(nameResults) == 0 {
		return "", "", fmt.Errorf("name() returned no results")
	}
	tokenName, ok := nameResults[0].(string)
	if !ok {
		return "", "", fmt.Errorf("name() returned invalid type")
	}

	// Get token version
	versionContract := bind.NewBoundContract(tokenAddr, versionParsed, tcu.client, tcu.client, tcu.client)
	var versionResults []interface{}
	err = versionContract.Call(callOpts, &versionResults, "version")
	if err != nil {
		// Version might not exist, use default
		return tokenName, "1", nil
	}
	if len(versionResults) == 0 {
		return tokenName, "1", nil
	}
	tokenVersion, ok := versionResults[0].(string)
	if !ok {
		return tokenName, "1", nil
	}

	return tokenName, tokenVersion, nil
}

// GetTokenBalance returns the account's ERC20 token balance
func (tcu *TokenContractUtils) GetTokenBalance(ownerAddress string) (*big.Int, error) {
	return tcu.GetTokenBalanceWithContext(ownerAddress, context.Background())
}

func (tcu *TokenContractUtils) GetTokenBalanceWithContext(ownerAddress string, ctx context.Context) (*big.Int, error) {
	tokenAddr := common.HexToAddress(tcu.tokenAddress)
	ownerAddr := common.HexToAddress(ownerAddress)

	// Test connection with a simple call
	_, err := tcu.client.ChainID(ctx)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("client connection failed: %w", err)
	}

	// ERC20 balanceOf function ABI
	balanceABI := `[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]`

	parsedABI, err := abi.JSON(strings.NewReader(balanceABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse balanceOf ABI: %w", err)
	}

	// Use bind.Call for proper ABI encoding/decoding
	callOpts := &bind.CallOpts{
		Pending: false,
		Context: ctx,
	}

	boundContract := bind.NewBoundContract(tokenAddr, parsedABI, tcu.client, tcu.client, tcu.client)
	var results []interface{}
	err = boundContract.Call(callOpts, &results, "balanceOf", ownerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to call balanceOf: %w", err)
	}

	if len(results) == 0 {
		return big.NewInt(0), nil
	}

	balance, ok := results[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid balance type returned")
	}

	return balance, nil
}

// GetDomainSeparator fetches the actual domain separator from the contract
func (tcu *TokenContractUtils) GetDomainSeparator(ctx context.Context) ([]byte, error) {
	tokenAddr := common.HexToAddress(tcu.tokenAddress)
	// DOMAIN_SEPARATOR() function ABI
	domainABI := `[{"constant":true,"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"name":"","type":"bytes32"}],"type":"function"}]`

	domainParsed, err := abi.JSON(strings.NewReader(domainABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse domain separator ABI: %w", err)
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		Context: ctx,
	}

	domainContract := bind.NewBoundContract(tokenAddr, domainParsed, tcu.client, tcu.client, tcu.client)
	var results []interface{}
	err = domainContract.Call(callOpts, &results, "DOMAIN_SEPARATOR")
	if err != nil {
		return nil, fmt.Errorf("failed to call DOMAIN_SEPARATOR: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("DOMAIN_SEPARATOR returned no results")
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
