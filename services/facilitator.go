package services

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shopspring/decimal"

	"go-x402-facilitator/blockchain"
	"go-x402-facilitator/config"
	"go-x402-facilitator/models"
	"go-x402-facilitator/state"
)

// FacilitatorService handles facilitator operations
type FacilitatorService struct {
	config *config.Config
	client *ethclient.Client
	token  *blockchain.ERC20Contract
}

// NewFacilitatorService creates a new facilitator service
func NewFacilitatorService(cfg *config.Config) (*FacilitatorService, error) {
	client, err := ethclient.Dial(cfg.BlockchainRPC)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to blockchain: %w", err)
	}

	tokenAddress := common.HexToAddress(cfg.ERC20TokenAddress)
	token, err := blockchain.NewERC20Contract(client, tokenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create ERC20 contract instance: %w", err)
	}

	return &FacilitatorService{
		config: cfg,
		client: client,
		token:  token,
	}, nil
}

// ProcessPayment processes a payment request
func (fs *FacilitatorService) ProcessPayment(facilitatorName string, req *models.PaymentRequest) (*models.PaymentResponse, error) {
	var privateKey string
	var feeBps int

	switch facilitatorName {
	case "alpha":
		privateKey = fs.config.AlphaPrivateKey
		feeBps = 50 // 0.5%
	case "beta":
		privateKey = fs.config.BetaPrivateKey
		feeBps = 100 // 1.0%
	case "gamma":
		privateKey = fs.config.GammaPrivateKey
		feeBps = 200 // 2.0%
	case "settle":
		privateKey = fs.config.SettlePrivateKey
		feeBps = 0 // 0% fee - matching Coinbase x402
	default:
		return nil, fmt.Errorf("unknown facilitator: %s", facilitatorName)
	}

	if privateKey == "" {
		return nil, fmt.Errorf("private key not configured for facilitator: %s", facilitatorName)
	}

	// Check native balance for gas
	if err := fs.checkNativeBalance(privateKey); err != nil {
		return nil, err
	}

	// Get token decimals
	tokenInfo, err := fs.token.GetTokenInfo(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get token info: %w", err)
	}

	// Check if this is a permit flow
	if req.Owner != "" && req.V != 0 && req.R != "" && req.S != "" && req.Deadline != "" && req.Value != "" {
		return fs.processPermitFlow(facilitatorName, privateKey, req, tokenInfo.Decimals, feeBps)
	} else {
		return fs.processDirectTransfer(facilitatorName, privateKey, tokenInfo.Decimals, feeBps)
	}
}

// processPermitFlow handles EIP-2612 permit flow
func (fs *FacilitatorService) processPermitFlow(facilitatorName, privateKey string, req *models.PaymentRequest, decimals uint8, feeBps int) (*models.PaymentResponse, error) {
	// Parse values
	deadline, err := strconv.ParseUint(req.Deadline, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid deadline: %w", err)
	}

	value, ok := new(big.Int).SetString(req.Value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid value")
	}

	// Convert hex strings to bytes
	rBytes, err := hexToBytes(req.R)
	if err != nil {
		return nil, fmt.Errorf("invalid r: %w", err)
	}

	sBytes, err := hexToBytes(req.S)
	if err != nil {
		return nil, fmt.Errorf("invalid s: %w", err)
	}

	var r, s [32]byte
	copy(r[:], rBytes)
	copy(s[:], sBytes)

	owner := common.HexToAddress(req.Owner)
	walletAddress, err := fs.getAddressFromPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet address: %w", err)
	}

	// Execute permit
	if err := fs.token.Permit(privateKey, owner, walletAddress, value, big.NewInt(int64(deadline)), uint8(req.V), r, s); err != nil {
		state.IncrementFailure(facilitatorName)
		return nil, fmt.Errorf("permit failed: %w", err)
	}

	// Calculate fee and amount to merchant
	fee := new(big.Int).Mul(value, big.NewInt(int64(feeBps)))
	fee.Div(fee, big.NewInt(10000))
	amountToMerchant := new(big.Int).Sub(value, fee)

	// Execute transferFrom
	transferResp, err := fs.token.TransferFrom(privateKey, owner, common.HexToAddress(fs.config.MerchantWalletAddress), amountToMerchant, 0)
	if err != nil {
		state.IncrementFailure(facilitatorName)
		return nil, fmt.Errorf("transferFrom failed: %w", err)
	}

	// Calculate gas cost and format amount
	amountHuman := fs.formatAmount(amountToMerchant, decimals)

	// Update settlement state
	state.UpdateSettlement(facilitatorName, &models.Settlement{
		TxHash:             transferResp.TxHash,
		Amount:             amountHuman,
		To:                 fs.config.MerchantWalletAddress,
		GasCost:            transferResp.GasCost,
		Payer:              req.Owner,
		BlockNumber:        transferResp.BlockNumber,
		Timestamp:          time.Unix(transferResp.Timestamp, 0),
		FacilitatorAddress: transferResp.From,
		FeeBps:             feeBps,
	})

	return &models.PaymentResponse{
		Settled:            true,
		TxHash:             transferResp.TxHash,
		BlockNumber:        transferResp.BlockNumber,
		Facilitator:        strings.Title(facilitatorName),
		FacilitatorAddress: transferResp.From,
		Merchant:           fs.config.MerchantWalletAddress,
		Payer:              req.Owner,
		Amount:             amountHuman,
		FeeBps:             feeBps,
		Chain:              fs.config.GetChainName(),
		GasUsed:            strconv.FormatUint(transferResp.GasUsed, 10),
		GasCost:            transferResp.GasCost,
		Timestamp:          transferResp.Timestamp,
	}, nil
}

// processDirectTransfer handles direct transfer flow
func (fs *FacilitatorService) processDirectTransfer(facilitatorName, privateKey string, decimals uint8, feeBps int) (*models.PaymentResponse, error) {
	// For demo, transfer 1 token
	amount := fs.parseAmount("1", decimals)

	// Check ERC20 token balance
	walletAddress, err := fs.getAddressFromPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet address: %w", err)
	}

	balance, err := fs.token.GetBalanceOf(context.Background(), walletAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}

	if balance.Cmp(amount) < 0 {
		return nil, fmt.Errorf("insufficient ERC20 token balance: have %s, need %s",
			fs.formatAmount(balance, decimals),
			fs.formatAmount(amount, decimals))
	}

	// Get balance before
	balanceBefore, err := fs.token.GetBalanceOf(context.Background(), walletAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance before: %w", err)
	}

	// Execute transfer
	transferResp, err := fs.token.Transfer(privateKey, common.HexToAddress(fs.config.MerchantWalletAddress), amount, 0)
	if err != nil {
		state.IncrementFailure(facilitatorName)
		return nil, fmt.Errorf("transfer failed: %w", err)
	}

	// Get balance after
	balanceAfter, err := fs.token.GetBalanceOf(context.Background(), walletAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance after: %w", err)
	}

	// Update settlement state
	state.UpdateSettlement(facilitatorName, &models.Settlement{
		TxHash:             transferResp.TxHash,
		Amount:             "1.00 tokens",
		To:                 fs.config.MerchantWalletAddress,
		GasCost:            transferResp.GasCost,
		Payer:              walletAddress.Hex(),
		BlockNumber:        transferResp.BlockNumber,
		Timestamp:          time.Unix(transferResp.Timestamp, 0),
		FacilitatorAddress: transferResp.From,
		FeeBps:             feeBps,
	})

	return &models.PaymentResponse{
		Paid:               true,
		Facilitator:        strings.Title(facilitatorName),
		FacilitatorAddress: transferResp.From,
		Fee:                fmt.Sprintf("%.1f%%", float64(feeBps)/100),
		Amount:             "1.00 tokens",
		Asset:              fs.config.ERC20TokenAddress,
		Merchant:           fs.config.MerchantWalletAddress,
		TxHash:             transferResp.TxHash,
		Network:            fs.config.GetChainName(),
		BalanceBefore:      fs.formatAmount(balanceBefore, decimals),
		BalanceAfter:       fs.formatAmount(balanceAfter, decimals),
		BlockNumber:        transferResp.BlockNumber,
		GasCost:            transferResp.GasCost,
	}, nil
}

// TransferERC20 handles generic ERC20 token transfer
func (fs *FacilitatorService) TransferERC20(req *models.ContractInteraction) (*models.TransferResponse, error) {
	// Validate private key
	if req.PrivateKey == "" {
		return nil, fmt.Errorf("private key is required")
	}

	// Create ERC20 contract instance
	tokenAddress := common.HexToAddress(req.TokenAddress)
	token, err := blockchain.NewERC20Contract(fs.client, tokenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create token contract: %w", err)
	}

	// Get token info for decimals
	tokenInfo, err := token.GetTokenInfo(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get token info: %w", err)
	}

	// Parse amount
	amount, err := parseAmountString(req.Amount, tokenInfo.Decimals)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %w", err)
	}

	// Execute transfer
	destination := common.HexToAddress(req.Destination)
	response, err := token.Transfer(req.PrivateKey, destination, amount, req.GasLimit)
	if err != nil {
		return nil, fmt.Errorf("transfer failed: %w", err)
	}

	return response, nil
}

// Helper functions

func (fs *FacilitatorService) checkNativeBalance(privateKey string) error {
	walletAddress, err := fs.getAddressFromPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to get wallet address: %w", err)
	}

	balance, err := fs.client.BalanceAt(context.Background(), walletAddress, nil)
	if err != nil {
		return fmt.Errorf("failed to get native balance: %w", err)
	}

	if balance.Cmp(big.NewInt(0)) == 0 {
		return fmt.Errorf("facilitator wallet %s has no native tokens for gas. Please fund it with native tokens for the chain", walletAddress.Hex())
	}

	return nil
}

func (fs *FacilitatorService) getAddressFromPrivateKey(privateKey string) (common.Address, error) {
	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(privateKeyECDSA.PublicKey), nil
}

func (fs *FacilitatorService) formatAmount(amount *big.Int, decimals uint8) string {
	d := decimal.NewFromBigInt(amount, -int32(decimals))
	return d.String() + " tokens"
}

func (fs *FacilitatorService) parseAmount(amountStr string, decimals uint8) *big.Int {
	d, err := decimal.NewFromString(amountStr)
	if err != nil {
		// Fallback to 1 token
		d = decimal.NewFromInt(1)
	}

	d = d.Mul(decimal.New(1, int32(decimals)))
	amount := d.BigInt()
	if amount == nil {
		amount = big.NewInt(0)
	}
	return amount
}

func hexToBytes(hexStr string) ([]byte, error) {
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	return hex.DecodeString(hexStr)
}

func parseAmountString(amountStr string, decimals uint8) (*big.Int, error) {
	d, err := decimal.NewFromString(amountStr)
	if err != nil {
		return nil, err
	}

	d = d.Mul(decimal.New(1, int32(decimals)))
	bigInt := d.BigInt()
	if bigInt == nil {
		return big.NewInt(0), nil
	}
	return bigInt, nil
}
