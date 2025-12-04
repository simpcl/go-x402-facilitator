package facilitator

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	facilitatorTypes "github.com/x402/go-x402-facilitator/pkg/types"
	"github.com/x402/go-x402-facilitator/pkg/utils"
)

const (
	SCHEME_EXACT = "exact"
)

// EVMFacilitator handles EVM-based payment verification and settlement
type EVMFacilitator struct {
	client     *ethclient.Client
	chainID    int64
	usdcAddr   common.Address
	privateKey *ecdsa.PrivateKey
	auth       *bind.TransactOpts
}

// NewEVMFacilitator creates a new EVM facilitator instance
func NewEVMFacilitator(rpcURL string, chainID int64, usdcAddress string, privateKeyHex string) (*EVMFacilitator, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	usdcAddr := common.HexToAddress(usdcAddress)

	var privateKey *ecdsa.PrivateKey
	if privateKeyHex != "" {
		privateKey, err = crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(chainID))
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	return &EVMFacilitator{
		client:     client,
		chainID:    chainID,
		usdcAddr:   usdcAddr,
		privateKey: privateKey,
		auth:       auth,
	}, nil
}

// Verify verifies an exact EVM payment payload
func (f *EVMFacilitator) Verify(ctx context.Context, payload *facilitatorTypes.PaymentPayload, requirements *facilitatorTypes.PaymentRequirements) (*facilitatorTypes.VerifyResponse, error) {
	// Validate scheme
	if payload.Scheme != SCHEME_EXACT || requirements.Scheme != SCHEME_EXACT {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Payer:         "",
		}, nil
	}

	// Validate network
	if err := utils.ValidateNetwork(requirements.Network); err != nil {
		return &facilitatorTypes.VerifyResponse{
			IsValid:       false,
			InvalidReason: "invalid_network",
			Payer:         "",
		}, nil
	}

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
	// Create typed data for verification
	typedData := &facilitatorTypes.TypedData{
		Types: map[string][]facilitatorTypes.TypedDataField{
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
		Domain: facilitatorTypes.TypedDataDomain{
			Name:              "USDC",
			Version:           "2",
			ChainID:           big.NewInt(f.chainID),
			VerifyingContract: requirements.Asset,
		},
		Message: map[string]interface{}{
			"from":        payload.Authorization.From,
			"to":          payload.Authorization.To,
			"value":       payload.Authorization.Value,
			"validAfter":  payload.Authorization.ValidAfter,
			"validBefore": payload.Authorization.ValidBefore,
			"nonce":       payload.Authorization.Nonce,
		},
	}

	// Recover the address
	recoveredAddr, err := utils.RecoverAddress(typedData, payload.Signature)
	if err != nil {
		return fmt.Errorf("failed to recover address: %w", err)
	}

	// Verify the recovered address matches the expected address
	expectedAddr := common.HexToAddress(payload.Authorization.From)
	if recoveredAddr != expectedAddr {
		return fmt.Errorf("signature verification failed: address mismatch")
	}

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
		return fmt.Errorf(reason)
	}

	return nil
}

// verifyBalance verifies the sender has sufficient USDC balance
func (f *EVMFacilitator) verifyBalance(ctx context.Context, payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) error {
	balance, err := utils.CheckUSDCBalance(f.client, requirements.Network, payload.Authorization.From)
	if err != nil {
		return fmt.Errorf("failed to check balance: %w", err)
	}

	requiredAmount, ok := new(big.Int).SetString(requirements.MaxAmountRequired, 10)
	if !ok {
		return fmt.Errorf("invalid max amount required: %s", requirements.MaxAmountRequired)
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

// executeTransferWithAuthorization executes the USDC transferWithAuthorization function
func (f *EVMFacilitator) executeTransferWithAuthorization(ctx context.Context, payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) (common.Hash, error) {
	// USDC contract ABI (transferWithAuthorization function)
	usdcABIString := `[{
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

	usdcABI, err := abi.JSON(strings.NewReader(usdcABIString))
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse USDC ABI: %w", err)
	}

	// Parse signature
	sig, err := utils.ParseSignature(payload.Signature)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Extract v, r, s values
	var v uint8
	if sig.V != nil {
		v = uint8(sig.V.Uint64())
		if v == 0 || v == 1 {
			v += 27
		}
	}

	// Prepare arguments
	fromAddr := common.HexToAddress(payload.Authorization.From)
	toAddr := common.HexToAddress(payload.Authorization.To)
	value, _ := new(big.Int).SetString(payload.Authorization.Value, 10)
	validAfter, _ := new(big.Int).SetString(payload.Authorization.ValidAfter, 10)
	validBefore, _ := new(big.Int).SetString(payload.Authorization.ValidBefore, 10)
	nonce := common.HexToHash(payload.Authorization.Nonce)

	// Pack the function call data
	data, err := usdcABI.Pack(
		"transferWithAuthorization",
		fromAddr,
		toAddr,
		value,
		validAfter,
		validBefore,
		nonce,
		v,
		sig.R,
		sig.S,
	)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack function call: %w", err)
	}

	// Create and send transaction
	msg := ethereum.CallMsg{
		From:  f.auth.From,
		To:    &f.usdcAddr,
		Data:  data,
		Gas:   f.auth.GasLimit,
		Value: big.NewInt(0),
	}

	// Estimate gas
	gasLimit, err := f.client.EstimateGas(ctx, msg)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Send transaction
	tx := ethTypes.NewTransaction(
		f.auth.Nonce.Uint64(),
		f.usdcAddr,
		big.NewInt(0),
		gasLimit,
		f.auth.GasPrice,
		data,
	)
	err = f.client.SendTransaction(ctx, tx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	return tx.Hash(), nil
}

// waitForTransaction waits for transaction confirmation
func (f *EVMFacilitator) waitForTransaction(ctx context.Context, txHash common.Hash) (*TransactionReceipt, error) {
	// Poll for transaction receipt
	receipt, err := bind.WaitMined(ctx, f.client, &ethTypes.Transaction{})
	if err != nil {
		return nil, fmt.Errorf("failed to wait for transaction: %w", err)
	}

	return &TransactionReceipt{
		Status: receipt.Status,
	}, nil
}

// TransactionReceipt represents a transaction receipt
type TransactionReceipt struct {
	Status uint64
}

// ReceiptStatusSuccess represents successful transaction status
const ReceiptStatusSuccess = uint64(1)
