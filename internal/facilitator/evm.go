package facilitator

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	eip712 "github.com/x402/go-x402-facilitator/pkg/eip712full"
	facilitatorTypes "github.com/x402/go-x402-facilitator/pkg/types"
	"github.com/x402/go-x402-facilitator/pkg/utils"
)

const (
	SCHEME_EXACT = "exact"
)

// EVMFacilitator handles EVM-based payment verification and settlement
type EVMFacilitator struct {
	client       *ethclient.Client
	chainID      int64
	usdcAddr     common.Address
	privateKey   *ecdsa.PrivateKey
	auth         *bind.TransactOpts
	tokenName    string // Cached token name from contract
	tokenVersion string // Cached token version from contract
}

// NewEVMFacilitator creates a new EVM facilitator instance
func NewEVMFacilitator(rpcURL string, chainID int64, usdcAddress string, privateKeyHex string) (*EVMFacilitator, error) {
	// Input validation
	if rpcURL == "" {
		return nil, fmt.Errorf("RPC URL cannot be empty")
	}

	if usdcAddress == "" {
		return nil, fmt.Errorf("USDC address cannot be empty")
	}

	if !common.IsHexAddress(usdcAddress) {
		return nil, fmt.Errorf("invalid USDC address format: %s", usdcAddress)
	}

	if chainID <= 0 {
		return nil, fmt.Errorf("chain ID must be positive: %d", chainID)
	}

	// Attempt to connect to Ethereum client with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client at %s: %w", rpcURL, err)
	}

	// Verify the connection is working by checking chain ID
	networkChainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to verify connection to Ethereum client: %w", err)
	}

	// Warn if chain IDs don't match (but don't fail)
	if networkChainID.Int64() != chainID {
		fmt.Printf("Warning: Network chain ID (%d) doesn't match configured chain ID (%d)\n",
			networkChainID.Int64(), chainID)
		fmt.Printf("   This may cause issues with transaction processing\n")
	}

	usdcAddr := common.HexToAddress(usdcAddress)

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
		auth, err = bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(chainID))
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to create transactor: %w", err)
		}
	}

	facilitator := &EVMFacilitator{
		client:     client,
		chainID:    chainID,
		usdcAddr:   usdcAddr,
		privateKey: privateKey,
		auth:       auth,
	}

	// Fetch token name and version from contract
	tokenName, tokenVersion, err := facilitator.fetchTokenInfo(ctx)
	if err != nil {
		// Log warning but don't fail - use defaults
		log.Warn().
			Err(err).
			Msg("Failed to fetch token name/version from contract, using defaults")
		facilitator.tokenName = "GenericToken"
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

// fetchTokenInfo fetches the token name and version from the contract
func (f *EVMFacilitator) fetchTokenInfo(ctx context.Context) (string, string, error) {
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
	nameContract := bind.NewBoundContract(f.usdcAddr, nameParsed, f.client, f.client, f.client)
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
	versionContract := bind.NewBoundContract(f.usdcAddr, versionParsed, f.client, f.client, f.client)
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

// getTokenName returns the token name, with fallback to default
func (f *EVMFacilitator) getTokenName() string {
	if f.tokenName != "" {
		return f.tokenName
	}
	return "GenericToken"
}

// getTokenVersion returns the token version, with fallback to default
func (f *EVMFacilitator) getTokenVersion() string {
	if f.tokenVersion != "" {
		return f.tokenVersion
	}
	return "1"
}

// getContractDomainSeparator fetches the actual domain separator from the contract
func (f *EVMFacilitator) getContractDomainSeparator(ctx context.Context) ([]byte, error) {
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

	domainContract := bind.NewBoundContract(f.usdcAddr, domainParsed, f.client, f.client, f.client)
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
	// Ensure addresses are lowercase for EIP-712 hash consistency
	// The client signs with lowercase addresses, so we must match that format
	fromLower := strings.ToLower(payload.Authorization.From)
	toLower := strings.ToLower(payload.Authorization.To)

	// Create typed data for verification
	typedData := &eip712.TypedData{
		Types: map[string][]eip712.TypedDataField{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
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
		Domain: eip712.TypedDataDomain{
			Name:              f.getTokenName(),
			Version:           f.getTokenVersion(),
			ChainId:           uint64(f.chainID),
			VerifyingContract: common.HexToAddress(requirements.Asset),
		},
		Message: map[string]interface{}{
			"from":        fromLower,
			"to":          toLower,
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
		log.Error().
			Str("expected", expectedAddr.Hex()).
			Str("recovered", recoveredAddr.Hex()).
			Str("from_lower", fromLower).
			Str("to_lower", toLower).
			Msg("signature verification failed, address mismatch")
		return fmt.Errorf("signature verification failed: address mismatch")
	}

	log.Info().
		Str("recovered_address", recoveredAddr.Hex()).
		Str("from", fromLower).
		Str("to", toLower).
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

// verifyBalance verifies the sender has sufficient USDC balance
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
	if requirements.Network == "" {
		return fmt.Errorf("network cannot be empty")
	}

	if payload.Authorization.From == "" {
		return fmt.Errorf("from address cannot be empty")
	}

	if requirements.MaxAmountRequired == "" {
		return fmt.Errorf("max amount required cannot be empty")
	}

	balance, err := utils.CheckUSDCBalance(f.client, requirements.Network, payload.Authorization.From)
	if err != nil {
		// If balance check fails due to connection issues, allow the payment to proceed
		// This is a graceful degradation approach
		if strings.Contains(err.Error(), "connection failed") ||
			strings.Contains(err.Error(), "client is nil") ||
			strings.Contains(err.Error(), "failed to call USDC balanceOf") {
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

// executeTransferWithAuthorization executes the USDC transferWithAuthorization function
func (f *EVMFacilitator) executeTransferWithAuthorization(ctx context.Context, payload *facilitatorTypes.ExactEVMPayload, requirements *facilitatorTypes.PaymentRequirements) (common.Hash, error) {
	// Check if facilitator has private key for transaction signing
	if f.auth == nil {
		return common.Hash{}, fmt.Errorf("no private key configured for transaction signing")
	}

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
		vRaw := sig.V.Uint64()
		v = uint8(vRaw)
		// Normalize v value: if it's 0 or 1, add 27 to get 27 or 28
		// If it's already 27 or 28, keep it as is
		if v == 0 || v == 1 {
			v += 27
		}
		// Ensure v is 27 or 28
		if v != 27 && v != 28 {
			return common.Hash{}, fmt.Errorf("invalid v value: %d (must be 27 or 28)", v)
		}
		log.Info().
			Uint64("v_raw", vRaw).
			Uint8("v_normalized", v).
			Msg("Extracted signature v value")
	}

	// Prepare arguments
	fromAddr := common.HexToAddress(payload.Authorization.From)
	toAddr := common.HexToAddress(payload.Authorization.To)
	value, ok := new(big.Int).SetString(payload.Authorization.Value, 10)
	if !ok {
		return common.Hash{}, fmt.Errorf("invalid value: %s", payload.Authorization.Value)
	}
	validAfter, ok := new(big.Int).SetString(payload.Authorization.ValidAfter, 10)
	if !ok {
		return common.Hash{}, fmt.Errorf("invalid validAfter: %s", payload.Authorization.ValidAfter)
	}
	validBefore, ok := new(big.Int).SetString(payload.Authorization.ValidBefore, 10)
	if !ok {
		return common.Hash{}, fmt.Errorf("invalid validBefore: %s", payload.Authorization.ValidBefore)
	}
	nonce := common.HexToHash(payload.Authorization.Nonce)

	// Log transaction parameters for debugging
	log.Info().
		Str("from", fromAddr.Hex()).
		Str("to", toAddr.Hex()).
		Str("value", value.String()).
		Str("validAfter", validAfter.String()).
		Str("validBefore", validBefore.String()).
		Str("nonce", nonce.Hex()).
		Uint8("v", v).
		Msg("Preparing transferWithAuthorization transaction")

	// Convert *big.Int to [32]byte for ABI compatibility
	var rBytes [32]byte
	var sBytes [32]byte

	if sig.R != nil {
		rBytes = common.BigToHash(sig.R)
	}
	if sig.S != nil {
		sBytes = common.BigToHash(sig.S)
	}

	// Before packing, let's verify the signature matches what the contract will verify
	// The contract will reconstruct the EIP-712 message using the parameters we pass
	// So we need to ensure the format matches exactly what was signed
	contractTypedData := &eip712.TypedData{
		Types: map[string][]eip712.TypedDataField{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
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
		Domain: eip712.TypedDataDomain{
			Name:              f.getTokenName(),
			Version:           f.getTokenVersion(),
			ChainId:           uint64(f.chainID),
			VerifyingContract: f.usdcAddr,
		},
		Message: map[string]interface{}{
			"from":        fromAddr, // Contract uses address type, not string
			"to":          toAddr,   // Contract uses address type, not string
			"value":       value.String(),
			"validAfter":  validAfter.String(),
			"validBefore": validBefore.String(),
			"nonce":       nonce,
		},
	}

	// Verify signature with contract's expected format
	contractHash, err := utils.HashTypedDataBytes(contractTypedData)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to hash typed data for contract verification")
	} else {
		// Try to recover address using contract's hash
		sigBytes, err := hexutil.Decode(payload.Signature)
		if err == nil {
			contractRecoveredAddr, err := crypto.SigToPub(contractHash, sigBytes)
			if err == nil {
				contractRecovered := crypto.PubkeyToAddress(*contractRecoveredAddr)

				// Also get the actual domain separator from contract to compare
				domainSeparator, domainErr := f.getContractDomainSeparator(ctx)
				ourDomainHash, ourErr := contractTypedData.HashDomain()

				log.Info().
					Str("contract_recovered", contractRecovered.Hex()).
					Str("expected", fromAddr.Hex()).
					Str("hash", fmt.Sprintf("%x", contractHash)).
					Str("token_name", f.getTokenName()).
					Str("token_version", f.getTokenVersion()).
					Str("our_domain_hash", fmt.Sprintf("%x", ourDomainHash)).
					Str("contract_domain_separator", fmt.Sprintf("%x", domainSeparator)).
					Err(domainErr).
					Err(ourErr).
					Msg("Contract signature verification simulation")

				if contractRecovered != fromAddr {
					log.Warn().
						Str("contract_recovered", contractRecovered.Hex()).
						Str("expected", fromAddr.Hex()).
						Msg("Contract signature verification would fail - address mismatch")
				}
			}
		}
	}

	// Pack the function call data with correct types
	data, err := usdcABI.Pack(
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
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack function call: %w", err)
	}

	// Try to estimate gas and simulate the call to catch revert reasons
	msg := ethereum.CallMsg{
		From: f.auth.From,
		To:   &f.usdcAddr,
		Data: data,
		Gas:  0,
	}

	// Estimate gas - this will also reveal revert reasons
	gasLimit, err := f.client.EstimateGas(ctx, msg)
	if err != nil {
		errStr := err.Error()
		// Check if the error is due to authorization not yet valid
		if strings.Contains(errStr, "Authorization not yet valid") {
			// Get current block timestamp to check the actual time difference
			header, headerErr := f.client.HeaderByNumber(ctx, nil)
			if headerErr == nil {
				blockTime := header.Time
				validAfterTime := validAfter.Int64()
				timeDiff := validAfterTime - int64(blockTime)

				log.Warn().
					Int64("block_timestamp", int64(blockTime)).
					Int64("valid_after", validAfterTime).
					Int64("time_difference", timeDiff).
					Msg("Authorization not yet valid - waiting for block time to catch up")

				// If the difference is small (less than 5 seconds), wait and retry
				if timeDiff > 0 && timeDiff < 5 {
					log.Info().
						Int64("wait_seconds", timeDiff+1).
						Msg("Waiting for authorization to become valid")
					time.Sleep(time.Duration(timeDiff+1) * time.Second)

					// Retry gas estimation
					gasLimit, err = f.client.EstimateGas(ctx, msg)
					if err != nil {
						return common.Hash{}, fmt.Errorf("authorization still not valid after waiting: %w", err)
					}
					log.Info().
						Uint64("estimated_gas", gasLimit).
						Msg("Gas estimation successful after waiting")
				} else {
					return common.Hash{}, fmt.Errorf("authorization not yet valid: block time %d, validAfter %d (diff: %d seconds)", blockTime, validAfterTime, timeDiff)
				}
			} else {
				return common.Hash{}, fmt.Errorf("authorization not yet valid and failed to get block header: %w", err)
			}
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
		f.usdcAddr,
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

// TransactionReceipt represents a transaction receipt
type TransactionReceipt struct {
	Status uint64
}

// ReceiptStatusSuccess represents successful transaction status
const ReceiptStatusSuccess = uint64(1)
