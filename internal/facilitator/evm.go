package facilitator

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"crypto/ecdsa"

	facilitatorTypes "github.com/agent-guide/go-x402-facilitator/pkg/types"
	"github.com/agent-guide/go-x402-facilitator/pkg/utils"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
)

const (
	SCHEME_EXACT = "exact"
)

// TransactionReceipt represents a transaction receipt
type TransactionReceipt struct {
	Status uint64
}

// ReceiptStatusSuccess represents successful transaction status
const ReceiptStatusSuccess = uint64(1)

// EVMFacilitator handles EVM-based payment verification and settlement
type EVMFacilitator struct {
	client       *ethclient.Client
	chainID      uint64
	tokenAddress common.Address
	privateKey   *ecdsa.PrivateKey
	auth         *bind.TransactOpts
	tokenName    string // Cached token name from contract
	tokenVersion string // Cached token version from contract
}

// NewEVMFacilitator creates a new EVM facilitator instance
func NewEVMFacilitator(rpcURL string, chainID uint64, tokenAddr string, privateKeyHex string) (*EVMFacilitator, error) {
	// Input validation
	if rpcURL == "" {
		return nil, fmt.Errorf("RPC URL cannot be empty")
	}

	if tokenAddr == "" || !common.IsHexAddress(tokenAddr) {
		return nil, fmt.Errorf("invalid token contract address: %s", tokenAddr)
	}

	// Attempt to connect to Ethereum client with timeout
	// Use a longer timeout for initial connection (30 seconds)
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer connectCancel()

	client, err := ethclient.DialContext(connectCtx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client at %s: %w", rpcURL, err)
	}

	// Verify the connection is working by checking chain ID
	// Use a separate context with timeout for ChainID call to ensure sufficient time
	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer verifyCancel()

	networkChainID, err := client.ChainID(verifyCtx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to verify connection to Ethereum client: %w", err)
	}

	// Warn if chain IDs don't match (but don't fail)
	if networkChainID.Uint64() != chainID {
		fmt.Printf("Warning: Network chain ID (%d) doesn't match configured chain ID (%d)\n",
			networkChainID.Uint64(), chainID)
		fmt.Printf("   This may cause issues with transaction processing\n")
	}

	var privateKey *ecdsa.PrivateKey
	if privateKeyHex != "" {
		privateKey, err = crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
	}

	var auth *bind.TransactOpts
	if privateKey != nil {
		auth, err = bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(int64(chainID)))
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to create transactor: %w", err)
		}
	}

	tokenAddress := common.HexToAddress(tokenAddr)
	facilitator := &EVMFacilitator{
		client:       client,
		chainID:      chainID,
		tokenAddress: tokenAddress,
		privateKey:   privateKey,
		auth:         auth,
	}

	// Fetch token name and version from contract
	// Use a separate context with timeout for contract call
	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer fetchCancel()
	tokenName, tokenVersion, err := utils.FetchTokenInfoWithContext(fetchCtx, client, tokenAddress)
	if err != nil {
		// Log warning but don't fail - use defaults
		log.Warn().
			Err(err).
			Msg("Failed to fetch token name/version from contract, using defaults")
		facilitator.tokenName = "MyToken"
		facilitator.tokenVersion = "1"
	} else {
		facilitator.tokenName = tokenName
		facilitator.tokenVersion = tokenVersion
		log.Info().
			Str("token_name", tokenName).
			Str("token_version", tokenVersion).
			Msg("Fetched token info from contract")
	}

	return facilitator, nil
}

// getTokenName returns the token name, with fallback to default
func (f *EVMFacilitator) getTokenName() string {
	return f.tokenName
}

// getTokenVersion returns the token version, with fallback to default
func (f *EVMFacilitator) getTokenVersion() string {
	return f.tokenVersion
}

// Verify verifies an exact EVM payment payload
func (f *EVMFacilitator) Verify(ctx context.Context, payload *facilitatorTypes.PaymentPayload, requirements *facilitatorTypes.PaymentRequirements) (*facilitatorTypes.VerifyResponse, error) {
	// Extract exact EVM payload
	exactPayload, err := f.extractExactEVMPayload(payload)
	if err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "invalid_payload_format",
			Payer:         "",
		}, nil
	}

	// Verify typed data signature
	if err := f.verifySignature(exactPayload, requirements); err != nil {
		log.Error().Err(err).Msg("Invalid signature")
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "invalid_signature",
			Payer:         exactPayload.Authorization.From,
		}, nil
	}

	// Verify recipient matches
	if err := f.verifyRecipient(exactPayload, requirements); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "recipient_mismatch",
			Payer:         exactPayload.Authorization.From,
		}, nil
	}

	// Verify time window
	if err := f.verifyTimeWindow(exactPayload); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: err.Error(),
			Payer:         exactPayload.Authorization.From,
		}, nil
	}

	// Verify sufficient balance
	if err := f.verifyBalance(ctx, exactPayload, requirements); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "insufficient_funds",
			Payer:         exactPayload.Authorization.From,
		}, nil
	}

	// Verify value meets requirements
	if err := f.verifyValue(exactPayload, requirements); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "insufficient_value",
			Payer:         exactPayload.Authorization.From,
		}, nil
	}

	return &facilitatorTypes.VerifyResponse{
		IsValid:       true,
		InvalidReason: "",
		Payer:         exactPayload.Authorization.From,
	}, nil
}

// Settle settles an exact EVM payment by executing the transferWithAuthorization transaction
func (f *EVMFacilitator) Settle(ctx context.Context, payload *facilitatorTypes.PaymentPayload, requirements *facilitatorTypes.PaymentRequirements) (*facilitatorTypes.SettleResponse, error) {
	// First verify the payment is still valid
	verifyResp, err := f.Verify(ctx, payload, requirements)
	if err != nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "verification_failed",
			Transaction: "",
			Network:     payload.Network,
			Payer:       "",
		}, err
	}

	if !verifyResp.IsValid {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: verifyResp.InvalidReason,
			Transaction: "",
			Network:     payload.Network,
			Payer:       verifyResp.Payer,
		}, nil
	}

	exactPayload, err := f.extractExactEVMPayload(payload)
	if err != nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "invalid_payload",
			Transaction: "",
			Network:     payload.Network,
			Payer:       "",
		}, err
	}

	// Execute transferWithAuthorization
	txHash, err := f.executeTransferWithAuthorization(ctx, exactPayload, requirements)
	if err != nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "transaction_failed",
			Transaction: "",
			Network:     payload.Network,
			Payer:       exactPayload.Authorization.From,
		}, err
	}

	// Wait for transaction confirmation
	receipt, err := f.waitForTransaction(ctx, txHash)
	if err != nil {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "confirmation_failed",
			Transaction: txHash.Hex(),
			Network:     payload.Network,
			Payer:       exactPayload.Authorization.From,
		}, err
	}

	if receipt.Status != ReceiptStatusSuccess {
		return &facilitatorTypes.SettleResponse{
			Success:     false,
			ErrorReason: "transaction_reverted",
			Transaction: txHash.Hex(),
			Network:     payload.Network,
			Payer:       exactPayload.Authorization.From,
		}, nil
	}

	return &facilitatorTypes.SettleResponse{
		Success:     true,
		ErrorReason: "",
		Transaction: txHash.Hex(),
		Network:     payload.Network,
		Payer:       exactPayload.Authorization.From,
	}, nil
}

// extractExactEVMPayload extracts the exact EVM payload from the generic payment payload
func (f *EVMFacilitator) extractExactEVMPayload(payload *facilitatorTypes.PaymentPayload) (*facilitatorTypes.ExactEVMPayload, error) {
	payloadData, ok := payload.Payload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid payload format")
	}

	signature, ok := payloadData["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("missing signature in payload")
	}

	authData, ok := payloadData["authorization"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing authorization in payload")
	}

	from, ok := authData["from"].(string)
	if !ok {
		return nil, fmt.Errorf("missing from in authorization")
	}

	to, ok := authData["to"].(string)
	if !ok {
		return nil, fmt.Errorf("missing to in authorization")
	}

	value, ok := authData["value"].(string)
	if !ok {
		return nil, fmt.Errorf("missing value in authorization")
	}

	validAfter, ok := authData["validAfter"].(string)
	if !ok {
		return nil, fmt.Errorf("missing validAfter in authorization")
	}

	validBefore, ok := authData["validBefore"].(string)
	if !ok {
		return nil, fmt.Errorf("missing validBefore in authorization")
	}

	nonce, ok := authData["nonce"].(string)
	if !ok {
		return nil, fmt.Errorf("missing nonce in authorization")
	}

	return &facilitatorTypes.ExactEVMPayload{
		Signature: signature,
		Authorization: facilitatorTypes.Authorization{
			From:        from,
			To:          to,
			Value:       value,
			ValidAfter:  validAfter,
			ValidBefore: validBefore,
			Nonce:       nonce,
		},
	}, nil
}

// verifySignature verifies the EIP-712 signature
func (f *EVMFacilitator) verifySignature(payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) error {
	typedData := utils.BuildTypedData(
		payload.Authorization.From,
		payload.Authorization.To,
		payload.Authorization.Value,
		payload.Authorization.ValidAfter,
		payload.Authorization.ValidBefore,
		payload.Authorization.Nonce,
		requirements.Asset,
		uint64(f.chainID),
		f.getTokenName(),
		f.getTokenVersion(),
	)

	// Recover the address
	recoveredAddr, err := utils.RecoverAddress(typedData, payload.Signature)
	if err != nil {
		return fmt.Errorf("failed to recover address: %w", err)
	}

	// Verify the recovered address matches the expected address
	expectedAddr := common.HexToAddress(payload.Authorization.From)
	if recoveredAddr != expectedAddr {
		log.Error().
			Str("expected", expectedAddr.Hex()).
			Str("recovered", recoveredAddr.Hex()).
			Str("from_lower", strings.ToLower(payload.Authorization.From)).
			Str("to_lower", strings.ToLower(payload.Authorization.To)).
			Msg("signature verification failed, address mismatch")
		return fmt.Errorf("signature verification failed: address mismatch")
	}

	log.Info().
		Str("recovered_address", recoveredAddr.Hex()).
		Str("from", strings.ToLower(payload.Authorization.From)).
		Str("to", strings.ToLower(payload.Authorization.To)).
		Msg("Signature verification successful")

	return nil
}

// verifyRecipient verifies the recipient matches the requirements
func (f *EVMFacilitator) verifyRecipient(payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) error {
	expected := strings.ToLower(requirements.PayTo)
	actual := strings.ToLower(payload.Authorization.To)

	if expected != actual {
		return fmt.Errorf("recipient mismatch: expected %s, got %s", expected, actual)
	}

	return nil
}

// verifyTimeWindow verifies the authorization time window is valid
func (f *EVMFacilitator) verifyTimeWindow(payload *facilitatorTypes.ExactEVMPayload) error {
	valid, reason := utils.IsValidTimestamp(
		payload.Authorization.ValidAfter,
		payload.Authorization.ValidBefore,
	)

	if !valid {
		return fmt.Errorf("%s", reason)
	}

	return nil
}

// verifyBalance verifies the sender has sufficient token balance
func (f *EVMFacilitator) verifyBalance(ctx context.Context, payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) error {
	// Input validation
	if f == nil {
		return fmt.Errorf("facilitator instance is nil")
	}

	if payload == nil {
		return fmt.Errorf("payload is nil")
	}

	if requirements == nil {
		return fmt.Errorf("requirements is nil")
	}

	// Check if Authorization fields are empty (struct cannot be nil)
	if payload.Authorization.From == "" && payload.Authorization.To == "" {
		return fmt.Errorf("authorization is empty")
	}

	// Check if client is available, if not, skip balance check gracefully
	if f.client == nil {
		// Log warning but don't fail the verification
		// This allows the system to work even when blockchain is not available
		fmt.Printf("Warning: Ethereum client is nil - skipping balance check\n")
		return nil
	}

	// Validate required fields
	if requirements.Asset == "" {
		return fmt.Errorf("asset cannot be empty")
	}

	if payload.Authorization.From == "" {
		return fmt.Errorf("from address cannot be empty")
	}

	if requirements.MaxAmountRequired == "" {
		return fmt.Errorf("max amount required cannot be empty")
	}

	// Check if client connection is actually working
	balance, err := utils.GetTokenBalanceWithContext(
		ctx,
		f.client,
		common.HexToAddress(requirements.Asset),
		common.HexToAddress(payload.Authorization.From),
	)
	if err != nil {
		// If balance check fails due to connection issues, allow the payment to proceed
		// This is a graceful degradation approach
		if strings.Contains(err.Error(), "client connection failed") ||
			strings.Contains(err.Error(), "failed to call token balanceOf") {
			fmt.Printf("Warning: Balance check failed due to blockchain connectivity issues: %v\n", err)
			fmt.Printf("   Proceeding with payment verification without balance check\n")
			return nil
		}
		return fmt.Errorf("failed to check balance: %w", err)
	}

	requiredAmount, ok := new(big.Int).SetString(requirements.MaxAmountRequired, 10)
	if !ok {
		return fmt.Errorf("invalid max amount required: %s", requirements.MaxAmountRequired)
	}

	// Check for negative amounts
	if requiredAmount.Sign() < 0 {
		return fmt.Errorf("max amount required cannot be negative: %s", requirements.MaxAmountRequired)
	}

	if balance.Cmp(requiredAmount) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s", balance.String(), requiredAmount.String())
	}

	return nil
}

// verifyValue verifies the payload value meets the requirements
func (f *EVMFacilitator) verifyValue(payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) error {
	payloadValue, ok := new(big.Int).SetString(payload.Authorization.Value, 10)
	if !ok {
		return fmt.Errorf("invalid payload value: %s", payload.Authorization.Value)
	}

	requiredAmount, ok := new(big.Int).SetString(requirements.MaxAmountRequired, 10)
	if !ok {
		return fmt.Errorf("invalid max amount required: %s", requirements.MaxAmountRequired)
	}

	if payloadValue.Cmp(requiredAmount) < 0 {
		return fmt.Errorf("insufficient payload value: have %s, need %s", payloadValue.String(), requiredAmount.String())
	}

	return nil
}

// executeTransferWithAuthorization executes the Token transferWithAuthorization function
func (f *EVMFacilitator) executeTransferWithAuthorization(ctx context.Context, payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) (common.Hash, error) {
	// Check if facilitator has private key for transaction signing
	if f.auth == nil {
		return common.Hash{}, fmt.Errorf("no private key configured for transaction signing")
	}

	// Parse signature
	sig, err := utils.ParseSignature(payload.Signature)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse signature: %w", err)
	}

	data, err := utils.PackTransferWithAuthorization(
		payload.Authorization.From,
		payload.Authorization.To,
		payload.Authorization.Value,
		payload.Authorization.ValidAfter,
		payload.Authorization.ValidBefore,
		payload.Authorization.Nonce,
		sig.V, sig.R, sig.S)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack function call: %w", err)
	}

	// Try to estimate gas and simulate the call to catch revert reasons
	msg := ethereum.CallMsg{
		From: f.auth.From,
		To:   &f.tokenAddress,
		Data: data,
		Gas:  0,
	}

	// Estimate gas - this will also reveal revert reasons
	gasLimit, err := f.client.EstimateGas(ctx, msg)
	if err != nil {
		errStr := err.Error()
		// Check if the error is due to authorization not yet valid
		if strings.Contains(errStr, "Authorization not yet valid") {
			header, headerErr := f.client.HeaderByNumber(ctx, nil)
			if headerErr == nil {
				blockTime := header.Time
				log.Warn().
					Int64("block_timestamp", int64(blockTime)).
					Str("valid_after", payload.Authorization.ValidAfter).
					Msg("Authorization not yet valid - waiting for block time to catch up")
			}
			return common.Hash{}, err
		} else {
			log.Warn().
				Err(err).
				Msg("Gas estimation failed - transaction may revert")
			// Continue with default gas limit, but log the error
			gasLimit = uint64(210000)
		}
	} else {
		// Add 20% buffer to estimated gas
		gasLimit = gasLimit + gasLimit/5
		log.Info().
			Uint64("estimated_gas", gasLimit).
			Msg("Gas estimation successful")
	}

	// gasLimit is already set from the estimation above

	// Get transaction nonce - use pending nonce if not set in auth
	var txNonce uint64
	if f.auth.Nonce != nil {
		txNonce = f.auth.Nonce.Uint64()
	} else {
		// Get pending nonce from the network
		pendingNonce, err := f.client.PendingNonceAt(ctx, f.auth.From)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to get pending nonce: %w", err)
		}
		txNonce = pendingNonce
	}

	// Determine gas price - use suggested price if not set in auth
	var gasPrice *big.Int
	if f.auth.GasPrice != nil {
		gasPrice = f.auth.GasPrice
	} else {
		// Get suggested gas price
		suggestedPrice, err := f.client.SuggestGasPrice(ctx)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to get suggested gas price: %w", err)
		}
		gasPrice = suggestedPrice
	}

	// Send transaction
	// Note: transaction value must be 0 for ERC20 token transfers
	// The token amount is already included in the contract call data
	tx := ethTypes.NewTransaction(
		txNonce,
		f.tokenAddress,
		big.NewInt(0), // Transaction value must be 0 for ERC20 transfers
		gasLimit,
		gasPrice,
		data,
	)

	// Sign the transaction with EIP-155 replay protection
	signedTx, err := f.auth.Signer(f.auth.From, tx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = f.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	log.Info().Str("txHash", signedTx.Hash().Hex()).Msg("Transaction sent successfully")
	return signedTx.Hash(), nil
}

// waitForTransaction waits for transaction confirmation
func (f *EVMFacilitator) waitForTransaction(ctx context.Context, txHash common.Hash) (*TransactionReceipt, error) {
	// Get the transaction by hash first
	tx, pending, err := f.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction by hash: %w", err)
	}

	// If transaction is pending, wait for it to be mined
	if pending {
		receipt, err := bind.WaitMined(ctx, f.client, tx)
		if err != nil {
			return nil, fmt.Errorf("failed to wait for transaction: %w", err)
		}
		return &TransactionReceipt{
			Status: receipt.Status,
		}, nil
	}

	// If transaction is already mined, get its receipt directly
	receipt, err := f.client.TransactionReceipt(ctx, txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	return &TransactionReceipt{
		Status: receipt.Status,
	}, nil
}

// Close closes the underlying Ethereum client connection
func (f *EVMFacilitator) Close() error {
	if f.client != nil {
		f.client.Close()
	}
	return nil
}
