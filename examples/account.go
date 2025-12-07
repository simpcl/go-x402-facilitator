package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"go-x402-facilitator/pkg/utils"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Common constants
const (
	ChainNetwork   = "localhost"
	ChainRPC       = "http://127.0.0.1:8545"
	ChainID        = 1337
	TokenContract  = "0xC35898F0f03C0894107869844d7467Af417aD868"
	FacilitatorURL = "http://localhost:8080"
)

// Account represents a participant in the payment flow
type Account struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
	Client     *ethclient.Client
	Auth       *bind.TransactOpts
}

// NewAccount creates a new account with the given private key
func NewAccount(privateKeyHex string) (*Account, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get address
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Connect to Ethereum client
	client, err := ethclient.Dial(ChainRPC)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	// Create transaction auth
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(ChainID))
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	return &Account{
		PrivateKey: privateKey,
		Address:    address,
		Client:     client,
		Auth:       auth,
	}, nil
}

// GetBalance returns the account's native token balance
func (a *Account) GetBalance() (*big.Int, error) {
	balance, err := a.Client.BalanceAt(context.Background(), a.Address, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	return balance, nil
}

// GetTokenBalance returns the account's ERC20 token balance
func (a *Account) GetTokenBalance() (*big.Int, error) {
	tcu := utils.NewTokenContractUtils(TokenContract, a.Client)
	balance, err := tcu.GetTokenBalance(a.Address.Hex())
	if err != nil {
		return nil, fmt.Errorf("failed to get token balance: %w", err)
	}
	return balance, nil
}

// WaitForReceipt waits for transaction confirmation
func (a *Account) WaitForReceipt(txHash common.Hash) error {
	for {
		receipt, err := a.Client.TransactionReceipt(context.Background(), txHash)
		if err != nil {
			if err == ethereum.NotFound {
				time.Sleep(2 * time.Second)
				continue
			}
			return fmt.Errorf("failed to get receipt: %w", err)
		}

		if receipt.Status == 1 {
			return nil
		}

		return fmt.Errorf("transaction failed")
	}
}

// PrintAccountInfo prints account information
func (a *Account) PrintAccountInfo(accountName string) {
	fmt.Printf("=== %s Account ===\n", accountName)
	fmt.Printf("Address: %s\n", a.Address.Hex())

	// Get native balance
	nativeBalance, err := a.GetBalance()
	if err != nil {
		fmt.Printf("Native Balance: Unable to fetch (%v)\n", err)
	} else {
		fmt.Printf(
			"Native Balance: %s wei (%.2f ETH)\n",
			nativeBalance.String(),
			new(big.Float).Quo(new(big.Float).SetInt(nativeBalance), big.NewFloat(1e18)),
		)
	}

	// Get token balance
	tokenBalance, err := a.GetTokenBalance()
	if err != nil {
		fmt.Printf("Token Balance: %s tokens\n", tokenBalance.String())
	} else {
		fmt.Printf("Token Balance: %s tokens\n", tokenBalance.String())
	}
}
