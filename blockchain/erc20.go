package blockchain

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"go-x402-facilitator/models"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ERC20Contract wraps ERC20 token contract interactions
type ERC20Contract struct {
	client   *ethclient.Client
	contract *bind.BoundContract
	address  common.Address
}

// NewERC20Contract creates a new ERC20 contract instance
func NewERC20Contract(client *ethclient.Client, address common.Address) (*ERC20Contract, error) {
	// ERC20 ABI fragments
	erc20ABI := `[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},{"constant":false,"inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"type":"function"},{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"nonces","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":false,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"deadline","type":"uint256"},{"name":"v","type":"uint8"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],"name":"permit","outputs":[],"type":"function"}]`

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ERC20 ABI: %w", err)
	}

	return &ERC20Contract{
		client:   client,
		contract: bind.NewBoundContract(address, parsedABI, client, client, client),
		address:  address,
	}, nil
}

// GetTokenInfo returns basic token information
func (erc20 *ERC20Contract) GetTokenInfo(ctx context.Context) (*models.ERC20Token, error) {
	var name []interface{}
	var symbol []interface{}
	var decimals []interface{}
	var totalSupply []interface{}

	// Call view functions
	if err := erc20.contract.Call(nil, &name, "name"); err != nil {
		return nil, fmt.Errorf("failed to get token name: %w", err)
	}

	if err := erc20.contract.Call(nil, &symbol, "symbol"); err != nil {
		return nil, fmt.Errorf("failed to get token symbol: %w", err)
	}

	if err := erc20.contract.Call(nil, &decimals, "decimals"); err != nil {
		return nil, fmt.Errorf("failed to get token decimals: %w", err)
	}

	if err := erc20.contract.Call(nil, &totalSupply, "totalSupply"); err != nil {
		return nil, fmt.Errorf("failed to get token total supply: %w", err)
	}

	// Extract values
	var nameStr string
	if len(name) > 0 {
		nameStr, _ = name[0].(string)
	}

	var symbolStr string
	if len(symbol) > 0 {
		symbolStr, _ = symbol[0].(string)
	}

	var decimalsUint8 uint8
	if len(decimals) > 0 {
		decimalsUint8, _ = decimals[0].(uint8)
	}

	var totalSupplyBig *big.Int
	if len(totalSupply) > 0 {
		totalSupplyBig, _ = totalSupply[0].(*big.Int)
	}

	return &models.ERC20Token{
		Address:     erc20.address.Hex(),
		Name:        nameStr,
		Symbol:      symbolStr,
		Decimals:    decimalsUint8,
		TotalSupply: totalSupplyBig,
	}, nil
}

// GetBalanceOf returns the balance of an address
func (erc20 *ERC20Contract) GetBalanceOf(ctx context.Context, address common.Address) (*big.Int, error) {
	var balance []interface{}

	if err := erc20.contract.Call(&bind.CallOpts{Context: ctx}, &balance, "balanceOf", address); err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}

	if len(balance) > 0 {
		if bal, ok := balance[0].(*big.Int); ok {
			return bal, nil
		}
	}

	return big.NewInt(0), nil
}

// GetNonce returns the nonce for EIP-2612 permit
func (erc20 *ERC20Contract) GetNonce(ctx context.Context, address common.Address) (*big.Int, error) {
	var nonce []interface{}

	if err := erc20.contract.Call(&bind.CallOpts{Context: ctx}, &nonce, "nonces", address); err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	if len(nonce) > 0 {
		if n, ok := nonce[0].(*big.Int); ok {
			return n, nil
		}
	}

	return big.NewInt(0), nil
}

// Transfer transfers tokens to a destination address
func (erc20 *ERC20Contract) Transfer(privateKeyHex string, destination common.Address, amount *big.Int, gasLimit uint64) (*models.TransferResponse, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Create transaction options
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337)) // Local blockchain Chain ID
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	// Set gas limit if provided
	if gasLimit > 0 {
		auth.GasLimit = gasLimit
	}

	// Get sender address
	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Execute transfer
	tx, err := erc20.contract.Transact(auth, "transfer", destination, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to transfer tokens: %w", err)
	}

	// Wait for transaction receipt
	receipt, err := bind.WaitMined(context.Background(), erc20.client, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for transaction: %w", err)
	}

	if receipt.Status != 1 {
		return nil, fmt.Errorf("transaction failed")
	}

	// Calculate gas cost in ETH
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), tx.GasPrice())

	return &models.TransferResponse{
		Success:      true,
		TxHash:       tx.Hash().Hex(),
		BlockNumber:  receipt.BlockNumber.Uint64(),
		GasUsed:      receipt.GasUsed,
		GasCost:      gasCost.String(),
		Amount:       amount.String(),
		From:         fromAddress.Hex(),
		To:           destination.Hex(),
		TokenAddress: erc20.address.Hex(),
		Timestamp:    time.Now().Unix(),
	}, nil
}

// Permit executes EIP-2612 permit function
func (erc20 *ERC20Contract) Permit(privateKeyHex string, owner, spender common.Address, value *big.Int, deadline *big.Int, v uint8, r, s [32]byte) error {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Create transaction options
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337)) // Local blockchain Chain ID
	if err != nil {
		return fmt.Errorf("failed to create transactor: %w", err)
	}

	// Execute permit
	tx, err := erc20.contract.Transact(auth, "permit", owner, spender, value, deadline, v, r, s)
	if err != nil {
		return fmt.Errorf("failed to execute permit: %w", err)
	}

	// Wait for transaction receipt
	receipt, err := bind.WaitMined(context.Background(), erc20.client, tx)
	if err != nil {
		return fmt.Errorf("failed to wait for permit transaction: %w", err)
	}

	if receipt.Status != 1 {
		return fmt.Errorf("permit transaction failed")
	}

	return nil
}

// TransferFrom executes transferFrom with permit
func (erc20 *ERC20Contract) TransferFrom(privateKeyHex string, from, to common.Address, amount *big.Int, gasLimit uint64) (*models.TransferResponse, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Create transaction options
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337)) // Local blockchain Chain ID
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	// Set gas limit if provided
	if gasLimit > 0 {
		auth.GasLimit = gasLimit
	}

	// Execute transferFrom
	tx, err := erc20.contract.Transact(auth, "transferFrom", from, to, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to transferFrom: %w", err)
	}

	// Wait for transaction receipt
	receipt, err := bind.WaitMined(context.Background(), erc20.client, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for transferFrom transaction: %w", err)
	}

	if receipt.Status != 1 {
		return nil, fmt.Errorf("transferFrom transaction failed")
	}

	// Calculate gas cost in ETH
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), tx.GasPrice())

	spenderAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &models.TransferResponse{
		Success:      true,
		TxHash:       tx.Hash().Hex(),
		BlockNumber:  receipt.BlockNumber.Uint64(),
		GasUsed:      receipt.GasUsed,
		GasCost:      gasCost.String(),
		Amount:       amount.String(),
		From:         from.Hex(),
		To:           to.Hex(),
		TokenAddress: erc20.address.Hex(),
		SpentBy:      spenderAddress.Hex(),
		Timestamp:    time.Now().Unix(),
	}, nil
}

// GetClient returns the underlying eth client
func (erc20 *ERC20Contract) GetClient() *ethclient.Client {
	return erc20.client
}
