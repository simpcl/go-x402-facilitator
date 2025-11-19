package services

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"go-x402-facilitator/models"
)

// VerifyService handles payment verification operations
type VerifyService struct {
	RPCURL string
}

// NewVerifyService creates a new verification service
func NewVerifyService(rpcURL string) *VerifyService {
	return &VerifyService{
		RPCURL: rpcURL,
	}
}

// VerifyPayment verifies a payment transaction on-chain
func (s *VerifyService) VerifyPayment(req *models.VerifyRequest) (*models.VerifyResponse, error) {
	// Validate input
	if req.TxHash == "" {
		return &models.VerifyResponse{
			Valid:     false,
			TxHash:    req.TxHash,
			Error:     "transaction hash is required",
			Message:   "Invalid request: missing transaction hash",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	// Validate transaction hash format
	if !strings.HasPrefix(req.TxHash, "0x") || len(req.TxHash) != 66 {
		return &models.VerifyResponse{
			Valid:     false,
			TxHash:    req.TxHash,
			Error:     "invalid transaction hash format",
			Message:   "Transaction hash must be 32 bytes hex string with 0x prefix",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	// Connect to blockchain
	client, err := ethclient.Dial(s.RPCURL)
	if err != nil {
		return &models.VerifyResponse{
			Valid:     false,
			TxHash:    req.TxHash,
			Error:     fmt.Sprintf("failed to connect to blockchain: %v", err),
			Message:   "Blockchain connection failed",
			Timestamp: time.Now().Unix(),
		}, nil
	}
	defer client.Close()

	// Get transaction receipt
	receipt, err := client.TransactionReceipt(nil, common.HexToHash(req.TxHash))
	if err != nil {
		return &models.VerifyResponse{
			Valid:     false,
			TxHash:    req.TxHash,
			Error:     fmt.Sprintf("transaction receipt not found: %v", err),
			Message:   "Transaction not found or not yet confirmed",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	// Check if transaction was successful
	if receipt.Status != 1 {
		return &models.VerifyResponse{
			Valid:     false,
			TxHash:    req.TxHash,
			Block:     receipt.BlockNumber.Uint64(),
			Error:     "transaction failed",
			Message:   "Transaction was reverted or failed",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	// Initialize response
	response := &models.VerifyResponse{
		Valid:     true,
		TxHash:    req.TxHash,
		Block:     receipt.BlockNumber.Uint64(),
		Timestamp: time.Now().Unix(),
	}

	// Find Transfer event logs from ERC20 token transfers
	transferFound := false
	for _, log := range receipt.Logs {
		// Transfer event topic for ERC20: Transfer(address,address,uint256)
		transferTopic := crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
		if len(log.Topics) > 0 && log.Topics[0] == transferTopic {
			transferFound = true
			// Extract addresses from topics
			if len(log.Topics) >= 3 {
				response.From = log.Topics[1].Hex()
				response.To = log.Topics[2].Hex()

				// Extract amount from data
				amount := new(big.Int)
				if len(log.Data) > 0 {
					amount.SetBytes(log.Data)
				}
				response.Amount = amount.String()
				break
			}
		}
	}

	// If no ERC20 Transfer event found, check if it's a native ETH transfer
	if !transferFound {
		// For native ETH transfers, we'd need to get the transaction details
		// For now, we'll indicate it's valid but no ERC20 transfer found
		response.Message = "Transaction confirmed but no ERC20 Transfer event found"
	} else {
		response.Message = "Payment verified successfully"
	}

	// Verify against expected values if provided
	if req.ExpectedPayer != "" {
		if response.From == "" {
			response.Valid = false
			response.Error = "cannot verify payer: no transfer information found"
			response.Message = "Unable to extract payer information from transaction"
		} else if strings.ToLower(response.From) != strings.ToLower(req.ExpectedPayer) {
			response.Valid = false
			response.Error = fmt.Sprintf("payer mismatch: expected %s, got %s", req.ExpectedPayer, response.From)
			response.Message = "Transaction payer does not match expected value"
		}
	}

	if req.ExpectedAmount != "" && response.Amount != "" {
		expectedAmount, ok := new(big.Int).SetString(req.ExpectedAmount, 10)
		if ok {
			actualAmount, _ := new(big.Int).SetString(response.Amount, 10)
			if actualAmount.Cmp(expectedAmount) < 0 {
				response.Valid = false
				response.Error = fmt.Sprintf("insufficient amount: expected >= %s, got %s", req.ExpectedAmount, response.Amount)
				response.Message = "Payment amount is less than expected"
			}
		}
	}

	return response, nil
}

// VerifyPaymentSimple provides simple verification without blockchain connection
func (s *VerifyService) VerifyPaymentSimple(txHash string) (*models.VerifyResponse, error) {
	response := &models.VerifyResponse{
		TxHash:    txHash,
		Timestamp: time.Now().Unix(),
	}

	// Basic validation of txHash format
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		response.Valid = false
		response.Error = "invalid transaction hash format"
		response.Message = "Transaction hash must be 32 bytes hex string with 0x prefix"
		return response, nil
	}

	// For demonstration, we'll do basic format validation and assume it's valid
	// In production, this would make an API call to a blockchain explorer
	response.Valid = true
	response.Message = "Transaction hash format is valid (mock verification)"
	return response, nil
}

// GetTransactionStatus retrieves the status of a transaction
func (s *VerifyService) GetTransactionStatus(txHash string) (bool, uint64, error) {
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		return false, 0, fmt.Errorf("invalid transaction hash format")
	}

	client, err := ethclient.Dial(s.RPCURL)
	if err != nil {
		return false, 0, fmt.Errorf("failed to connect to blockchain: %w", err)
	}
	defer client.Close()

	receipt, err := client.TransactionReceipt(nil, common.HexToHash(txHash))
	if err != nil {
		return false, 0, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	success := receipt.Status == 1
	return success, receipt.BlockNumber.Uint64(), nil
}

// CheckTokenBalance checks ERC20 token balance of an address
func (s *VerifyService) CheckTokenBalance(tokenAddress, userAddress string) (*big.Int, error) {
	// For demonstration purposes, return a mock balance
	// In production, this would make an actual eth_call RPC request to get token balance
	return big.NewInt(1000000), nil // 1 token with 6 decimals
}

// ParseAmount parses amount string with decimal support
func (s *VerifyService) ParseAmount(amountStr string, decimals uint8) (*big.Int, error) {
	if amountStr == "" {
		return big.NewInt(0), nil
	}

	// Try to parse as integer first (for wei/satoshi format)
	if amountInt, ok := new(big.Int).SetString(amountStr, 10); ok {
		return amountInt, nil
	}

	// For decimal amounts, convert to integer based on token decimals
	// This is a simplified version - production code would handle decimal parsing more robustly
	return nil, fmt.Errorf("unsupported amount format: %s", amountStr)
}

// ValidateAddress validates Ethereum address format
func (s *VerifyService) ValidateAddress(address string) bool {
	if !strings.HasPrefix(address, "0x") || len(address) != 42 {
		return false
	}

	// Check if it's a valid hex address
	addr := common.HexToAddress(address)
	return addr.Hex() != ""
}

// EstimateGasPrice estimates current gas price (mock implementation)
func (s *VerifyService) EstimateGasPrice() (string, error) {
	// Mock gas price - in production this would call eth_gasPrice
	return "5000000000", nil // 5 gwei
}

// GetChainID retrieves the current chain ID
func (s *VerifyService) GetChainID() (int64, error) {
	client, err := ethclient.Dial(s.RPCURL)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to blockchain: %w", err)
	}
	defer client.Close()

	chainID, err := client.ChainID(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to get chain ID: %w", err)
	}

	return chainID.Int64(), nil
}
