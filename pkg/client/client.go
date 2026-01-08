package client

import (
	"fmt"
	"strings"

	"github.com/agent-guide/go-x402-facilitator/pkg/types"
	"github.com/agent-guide/go-x402-facilitator/pkg/utils"
)

// CreatePaymentRequirements creates payment requirements for the seller
func CreatePaymentRequirements(
	scheme string,
	network string,
	payTo string,
	amount string,
	assetType string,
	asset string,
	resource string,
	description string,
	tokenName string,
	tokenVersion string,
) *types.PaymentRequirements {
	return &types.PaymentRequirements{
		Scheme:            scheme,
		Network:           network,
		Resource:          resource,
		Description:       description,
		MaxAmountRequired: amount,
		PayTo:             strings.ToLower(payTo),
		AssetType:         assetType,
		Asset:             strings.ToLower(asset),
		TokenName:         tokenName,
		TokenVersion:      tokenVersion,
	}
}

// CreatePaymentPayload creates a payment payload using the configured private key
func CreatePaymentPayload(
	requirements *types.PaymentRequirements,
	account *utils.Account,
	validAfter int64,
	validBefore int64,
	chainID uint64,
	nonce string,
) (*types.PaymentPayload, error) {

	tokenContractAddr := requirements.Asset

	// Build typed data
	typedData := utils.BuildTypedData(
		account.WalletAddress.Hex(),
		requirements.PayTo,
		requirements.MaxAmountRequired,
		fmt.Sprintf("%d", validAfter),
		fmt.Sprintf("%d", validBefore),
		nonce,
		tokenContractAddr,
		chainID,
		requirements.TokenName,
		requirements.TokenVersion,
	)

	// Generate signature
	signature, err := utils.GenerateTypedDataSignature(
		typedData,
		account.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature: %w", err)
	}

	// Create authorization
	auth := types.Authorization{
		From:        strings.ToLower(account.WalletAddress.Hex()),
		To:          strings.ToLower(requirements.PayTo),
		Value:       requirements.MaxAmountRequired,
		ValidAfter:  fmt.Sprintf("%d", validAfter),
		ValidBefore: fmt.Sprintf("%d", validBefore),
		Nonce:       nonce,
	}

	// Create exact EVM payload
	exactPayload := &types.ExactEVMPayload{
		Signature:     signature,
		Authorization: auth,
	}

	payload := &types.PaymentPayload{
		X402Version: 1,
		Scheme:      requirements.Scheme,
		Network:     requirements.Network,
		Payload:     *exactPayload,
	}

	return payload, nil
}
