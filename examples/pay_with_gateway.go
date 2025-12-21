package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	facilitatorTypes "go-x402-facilitator/pkg/types"
)

var (
	GatewayURL = "http://localhost:8080"
)

func init() {
	s := os.Getenv("GATEWAY_URL")
	if s != "" {
		GatewayURL = s
	}
}

// PaymentRequiredResponse represents the 402 Payment Required response
type PaymentRequiredResponse struct {
	Error               string                               `json:"error"`
	Message             string                               `json:"message"`
	Code                int                                  `json:"code"`
	PaymentRequirements facilitatorTypes.PaymentRequirements `json:"paymentRequirements"`
}

// Payer represents the payer in the X402 payment flow with gateway
type GatewayPayer struct {
	account *Account
}

// NewGatewayPayer creates a new gateway payer instance
func NewGatewayPayer() *GatewayPayer {
	privateKey := os.Getenv("PAYER_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatalln("ERROR: PAYER_PRIVATE_KEY environment variable is not set")
	}

	account, err := NewAccount(privateKey)
	if err != nil {
		log.Fatalf("ERROR: failed to create payer account: %v", err)
	}
	return &GatewayPayer{account: account}
}

// AccessResourceWithPayment accesses a resource through the gateway with X402 payment
func (p *GatewayPayer) AccessResourceWithPayment(resourcePath string) error {
	fmt.Println("=== Starting X402 Gateway Payment Process ===")

	// Print payer info
	p.account.PrintAccountInfo("Payer")

	tokenName, tokenVersion := p.account.GetTokenInfo()
	if tokenName == "" || tokenVersion == "" {
		return fmt.Errorf("failed to get token info")
	}
	fmt.Printf("Token name: %s, Token version: %s\n", tokenName, tokenVersion)

	// Step 1: Request resource without payment (expect 402)
	fmt.Printf("\n[Step 1] Requesting resource: %s\n", resourcePath)
	paymentReq, err := p.requestResourceWithoutPayment(resourcePath)
	if err != nil {
		return fmt.Errorf("failed to get payment requirements: %w", err)
	}

	fmt.Printf("✅ Received payment requirements:\n")
	fmt.Printf("   Scheme: %s\n", paymentReq.Scheme)
	fmt.Printf("   Network: %s\n", paymentReq.Network)
	fmt.Printf("   PayTo: %s\n", paymentReq.PayTo)
	fmt.Printf("   MaxAmountRequired: %s\n", paymentReq.MaxAmountRequired)
	fmt.Printf("   Resource: %s\n", paymentReq.Resource)
	fmt.Printf("   Description: %s\n", paymentReq.Description)

	// Step 2: Create payment payload
	fmt.Println("\n[Step 2] Creating payment payload...")
	payload, err := CreatePaymentPayload(
		p.account,
		paymentReq.PayTo,
		paymentReq.MaxAmountRequired,
		tokenName,
		tokenVersion,
	)
	if err != nil {
		return fmt.Errorf("failed to create payment payload: %w", err)
	}

	// Serialize payment payload to JSON for X-Payment header
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payment payload: %w", err)
	}

	fmt.Printf("✅ Payment payload created\n")

	// Step 3: Request resource with payment
	fmt.Println("\n[Step 3] Requesting resource with payment...")
	resourceResponse, err := p.requestResourceWithPayment(resourcePath, string(payloadJSON))
	if err != nil {
		return fmt.Errorf("failed to access resource with payment: %w", err)
	}

	fmt.Printf("✅ Resource accessed successfully!\n")
	fmt.Printf("   Response status: %d\n", resourceResponse.StatusCode)
	fmt.Printf("   Response body length: %d bytes\n", len(resourceResponse.Body))

	if len(resourceResponse.Body) > 0 {
		fmt.Printf("\n   Response preview (first 500 chars):\n")
		preview := resourceResponse.Body
		if len(preview) > 500 {
			preview = preview[:500] + "..."
		}
		fmt.Printf("   %s\n", preview)
	}

	return nil
}

// requestResourceWithoutPayment requests a resource without payment header
// Returns payment requirements from 402 response
func (p *GatewayPayer) requestResourceWithoutPayment(resourcePath string) (*facilitatorTypes.PaymentRequirements, error) {
	// Ensure resource path starts with /
	if !strings.HasPrefix(resourcePath, "/") {
		resourcePath = "/" + resourcePath
	}

	// Gateway API endpoint is /api/{path}
	url := fmt.Sprintf("%s/api%s", GatewayURL, resourcePath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusPaymentRequired {
		return nil, fmt.Errorf("expected 402 Payment Required, got %d: %s", resp.StatusCode, string(body))
	}

	var paymentResp PaymentRequiredResponse
	if err := json.Unmarshal(body, &paymentResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payment requirements: %w", err)
	}

	return &paymentResp.PaymentRequirements, nil
}

// requestResourceWithPayment requests a resource with X-Payment header
func (p *GatewayPayer) requestResourceWithPayment(resourcePath string, paymentPayloadJSON string) (*ResourceResponse, error) {
	// Ensure resource path starts with /
	if !strings.HasPrefix(resourcePath, "/") {
		resourcePath = "/" + resourcePath
	}

	// Gateway API endpoint is /api/{path}
	url := fmt.Sprintf("%s/api%s", GatewayURL, resourcePath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set X-Payment header
	req.Header.Set("X-Payment", paymentPayloadJSON)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second} // Longer timeout for payment processing
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return &ResourceResponse{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Headers:    resp.Header,
	}, nil
}

// ResourceResponse represents the response from accessing a resource
type ResourceResponse struct {
	StatusCode int
	Body       string
	Headers    http.Header
}

func main() {
	fmt.Println("=== X402 Gateway Payment Demo ===")

	// Create payer
	payer := NewGatewayPayer()

	// Check balance
	payer.account.PrintAccountInfo("Payer")

	// Get resource path from environment or use default
	resourcePath := os.Getenv("RESOURCE_PATH")
	if resourcePath == "" {
		resourcePath = "/premium-data" // Default resource path
		fmt.Printf("\nUsing default resource path: %s\n", resourcePath)
		fmt.Println("(Set RESOURCE_PATH environment variable to use a different path)")
	} else {
		fmt.Printf("\nUsing resource path from RESOURCE_PATH: %s\n", resourcePath)
	}

	fmt.Printf("Gateway URL: %s\n", GatewayURL)
	fmt.Println()

	// Access resource with payment
	if err := payer.AccessResourceWithPayment(resourcePath); err != nil {
		log.Fatalf("Payment failed: %v", err)
	}

	fmt.Println("\n=== Payment Process Complete ===")

	// Check final balance
	fmt.Println("\nFinal payer balance:")
	payer.account.PrintAccountInfo("Payer")
}
