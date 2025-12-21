package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"go-x402-facilitator/pkg/utils"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	ChainNetwork   = "localhost"
	ChainID        = uint64(1337)
	ChainRPC       = "http://127.0.0.1:8545"
	TokenContract  = "0xBA32c2Ee180e743cCe34CbbC86cb79278C116CEb"
	TokenName      = "MyToken"
	TokenVersion   = "1"
	FacilitatorURL = "http://localhost:8080"
)

func init() {
	var s string
	s = os.Getenv("CHAIN_NETWORK")
	if s != "" {
		ChainNetwork = s
	}
	s = os.Getenv("CHAIN_ID")
	if s != "" {
		var err error
		ChainID, err = strconv.ParseUint(s, 10, 64)
		if err != nil {
			fmt.Println("Error parsing ChainID:", err)
			os.Exit(-1)
		}
	}
	s = os.Getenv("CHAIN_RPC")
	if s != "" {
		ChainRPC = s
	}
	s = os.Getenv("TOKEN_CONTRACT")
	if s != "" {
		TokenContract = s
	}
	s = os.Getenv("TOKEN_NAME")
	if s != "" {
		TokenName = s
	}
	s = os.Getenv("TOKEN_VERSION")
	if s != "" {
		TokenVersion = s
	}
	s = os.Getenv("FACILITATOR_URL")
	if s != "" {
		FacilitatorURL = s
	}
}

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
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(int64(ChainID)))
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

// GetTokenInfo fetches token name and version from contract
func (a *Account) GetTokenInfo() (string, string) {
	client, err := ethclient.Dial(ChainRPC)
	if err != nil {
		fmt.Printf("Warning: Failed to connect to RPC, using defaults: %v\n", err)
		return TokenName, TokenVersion
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tcu := utils.NewTokenContractUtils(TokenContract, client)

	name, version, err := tcu.FetchTokenInfoWithContext(ctx)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch token info: %v\n", err)
		return TokenName, TokenVersion
	}
	return name, version
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
