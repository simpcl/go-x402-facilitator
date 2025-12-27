package utils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Account represents a participant in the payment flow
type Account struct {
	ChainRPCURL          string
	TokenContractAddress common.Address
	WalletAddress        common.Address
	Client               *ethclient.Client
	PrivateKey           *ecdsa.PrivateKey
}

// NewAccount creates a new account with the given private key
func NewAccount(chainRPCURL string, tokenContractAddr string, walletAddr string) (*Account, error) {
	if !common.IsHexAddress(tokenContractAddr) {
		return nil, fmt.Errorf("invalid token contract address format: %s", tokenContractAddr)
	}
	tokenContractAddress := common.HexToAddress(tokenContractAddr)

	if !common.IsHexAddress(walletAddr) {
		return nil, fmt.Errorf("invalid wallet address format: %s", walletAddr)
	}
	walletAddress := common.HexToAddress(walletAddr)

	// Connect to Ethereum client
	client, err := ethclient.Dial(chainRPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	return &Account{
		ChainRPCURL:          chainRPCURL,
		TokenContractAddress: tokenContractAddress,
		WalletAddress:        walletAddress,
		Client:               client,
	}, nil
}

// func NewAccountWithClient(client *ethclient.Client, privateKeyHex string) (*Account, error) {
func NewAccountWithPrivateKey(chainRPCURL string, tokenContractAddr string, privateKeyHex string) (*Account, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get address
	walletAddr := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	account, err := NewAccount(chainRPCURL, tokenContractAddr, walletAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}
	account.PrivateKey = privateKey

	return account, nil
}

// GetBalance returns the account's native token balance
func (a *Account) GetBalance() (*big.Int, error) {
	balance, err := a.Client.BalanceAt(context.Background(), a.WalletAddress, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	return balance, nil
}

// GetTokenBalance returns the account's ERC20 token balance
func (a *Account) GetTokenBalance() (*big.Int, error) {
	return GetTokenBalanceWithContext(context.Background(), a.Client, a.TokenContractAddress, a.WalletAddress)
}

// GetTokenInfo fetches token name and version from contract
func (a *Account) GetTokenInfo() (string, string) {
	getNameCtx, getNameCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer getNameCancel()
	tokenName, err := FetchTokenNameWithContext(getNameCtx, a.Client, a.TokenContractAddress)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch token name: %v\n", err)
		return "", ""
	}

	getVersionCtx, getVersionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer getVersionCancel()
	tokenVersion, err := FetchTokenVersionWithContext(getVersionCtx, a.Client, a.TokenContractAddress)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch token version: %v\n", err)
		return "", ""
	}
	return tokenName, tokenVersion
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
	fmt.Printf("\n--- %s Account ---\n", accountName)
	fmt.Printf("Chain RPC URL: %s\n", a.ChainRPCURL)
	fmt.Printf("Token Contract Address: %s\n", a.TokenContractAddress.Hex())
	fmt.Printf("Wallet Address: %s\n", a.WalletAddress.Hex())

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
	fmt.Printf("------------------------\n\n")
}
