package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	facilitatorTypes "github.com/agent-guide/go-x402-facilitator/pkg/types"
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
