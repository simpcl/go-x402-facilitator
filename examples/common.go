package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	facilitatorTypes "github.com/x402/go-x402-facilitator/pkg/types"
	"github.com/x402/go-x402-facilitator/pkg/utils"
)

// getTokenInfo fetches token name and version from contract
func getTokenInfo(contractAddress string) (string, string) {
	client, err := ethclient.Dial(ChainRPC)
	if err != nil {
		fmt.Printf("Warning: Failed to connect to RPC, using defaults: %v\n", err)
		return "GenericToken", "1"
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tcu := utils.NewTokenContractUtils(contractAddress, client)

	name, version, err := tcu.FetchTokenInfoWithContext(ctx)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch token info: %v\n", err)
		return "GenericToken", "1"
	}
	return name, version
}

// CreatePaymentPayload creates a complete X402 payment payload
func CreatePaymentPayload(
	account *Account,
	to string,
	value string,
	validDuration int64,
	verifyingContract string,
) (*facilitatorTypes.PaymentPayload, error) {

	now := time.Now().Unix()
	validAfter := now - 60000
	validBefore := now + validDuration

	// Generate nonce (simplified - in production, use a proper nonce generation)
	nonce := fmt.Sprintf("0x%x", crypto.Keccak256Hash([]byte(fmt.Sprintf("%d-%s-%s", now, account.Address.Hex(), to))).Hex())

	tokenName, tokenVersion := getTokenInfo(verifyingContract)

	typedData := utils.BuildTypedData(
		account.Address.Hex(),
		to,
		value,
		fmt.Sprintf("%d", validAfter),
		fmt.Sprintf("%d", validBefore),
		nonce,
		verifyingContract,
		ChainID,
		tokenName,
		tokenVersion,
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
	auth := facilitatorTypes.Authorization{
		From:        strings.ToLower(account.Address.Hex()),
		To:          strings.ToLower(to),
		Value:       value,
		ValidAfter:  fmt.Sprintf("%d", validAfter),
		ValidBefore: fmt.Sprintf("%d", validBefore),
		Nonce:       nonce,
	}

	// Create exact EVM payload
	exactPayload := &facilitatorTypes.ExactEVMPayload{
		Signature:     signature,
		Authorization: auth,
	}

	payload := &facilitatorTypes.PaymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     ChainNetwork,
		Payload:     *exactPayload,
	}

	return payload, nil
}

// CreatePaymentRequirements creates payment requirements for the seller
func CreatePaymentRequirements(
	sellerAddress string,
	amount string,
	resource string,
	description string,
	asset string,
) *facilitatorTypes.PaymentRequirements {
	return &facilitatorTypes.PaymentRequirements{
		Scheme:            "exact",
		Network:           ChainNetwork,
		MaxAmountRequired: amount,
		Resource:          resource,
		Description:       description,
		MimeType:          "application/json",
		PayTo:             strings.ToLower(sellerAddress),
		MaxTimeoutSeconds: 300, // 5 minutes
		Asset:             asset,
	}
}

// verifyPayment verifies the payment with the facilitator
func VerifyPayment(
	payload *facilitatorTypes.PaymentPayload,
	requirements *facilitatorTypes.PaymentRequirements,
) (*facilitatorTypes.VerifyResponse, error) {
	req := facilitatorTypes.VerifyRequest{
		PaymentPayload:      *payload,
		PaymentRequirements: *requirements,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", FacilitatorURL+"/facilitator/verify", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verification request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var verifyResp facilitatorTypes.VerifyResponse
	if err := json.Unmarshal(body, &verifyResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &verifyResp, nil
}

// settlePayment settles the payment with the facilitator
func SettlePayment(
	payload *facilitatorTypes.PaymentPayload,
	requirements *facilitatorTypes.PaymentRequirements,
) (*facilitatorTypes.SettleResponse, error) {
	req := facilitatorTypes.SettleRequest{
		PaymentPayload:      *payload,
		PaymentRequirements: *requirements,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", FacilitatorURL+"/facilitator/settle", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second} // Longer timeout for settlement
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("settlement request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var settleResp facilitatorTypes.SettleResponse
	if err := json.Unmarshal(body, &settleResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &settleResp, nil
}
