package main

import (
	"fmt"
	"log"
	"os"
)

func GetPayeeWalletAddress() string {
	payeeWalletAddress := os.Getenv("PAYEE_WALLET_ADDRESS")
	if payeeWalletAddress == "" {
		log.Fatalln("ERROR: PAYEE_WALLET_ADDRESS environment variable is not set")
	}
	return payeeWalletAddress
}

// Payer represents the payer in the X402 payment flow
type Payer struct {
	account *Account
}

// NewPayer creates a new payer instance
func NewPayer() *Payer {
	privateKey := os.Getenv("PAYER_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatalln("ERROR: PAYER_PRIVATE_KEY environment variable is not set")
	}

	account, err := NewAccount(privateKey)
	if err != nil {
		log.Fatalf("ERROR: failed to create payer account: %v", err)
	}
	return &Payer{account: account}
}

// MakePayment makes a payment to the payee
func (b *Payer) MakePayment(sellerAddress string, amount string, resource string, description string) error {
	fmt.Println("=== Starting X402 Payment Process ===")

	// Print payer info
	b.account.PrintAccountInfo("Payer")

	tokenName, tokenVersion := b.account.GetTokenInfo()
	if tokenName == "" || tokenVersion == "" {
		return fmt.Errorf("failed to get token info")
	}
	fmt.Printf("Token name: %s, Token version: %s\n", tokenName, tokenVersion)

	// Create payment requirements
	fmt.Println("Creating payment requirements...")
	requirements := CreatePaymentRequirements(
		sellerAddress,
		amount,
		resource,
		description,
		tokenName,
		tokenVersion,
	)

	// Create payment payload
	fmt.Println("Creating payment payload...")
	payload, err := CreatePaymentPayload(
		b.account,
		sellerAddress,
		amount,
		tokenName,
		tokenVersion,
	)
	if err != nil {
		return fmt.Errorf("failed to create payment payload: %w", err)
	}

	// Verify payment first
	fmt.Println("Verifying payment with facilitator...")
	verifyResp, err := VerifyPayment(payload, requirements)
	if err != nil {
		return fmt.Errorf("payment verification failed: %w", err)
	}

	if !verifyResp.IsValid {
		return fmt.Errorf("payment is invalid: %s", verifyResp.InvalidReason)
	}

	fmt.Printf("✅ Payment verification successful!\n")
	fmt.Printf("   Payer: %s\n", verifyResp.Payer)
	fmt.Printf("   Amount: %s\n", amount)

	// Ask user if they want to proceed with settlement
	fmt.Print("\nDo you want to proceed with payment settlement? (y/n): ")
	var response string
	fmt.Scanln(&response)

	if response != "y" && response != "Y" {
		fmt.Println("Payment settlement cancelled.")
		return nil
	}

	// Settle payment
	fmt.Println("Settling payment...")
	settleResp, err := SettlePayment(payload, requirements)
	if err != nil {
		return fmt.Errorf("payment settlement failed: %w", err)
	}

	if !settleResp.Success {
		return fmt.Errorf("payment settlement failed, settle resp: %s", settleResp.ErrorReason)
	}

	fmt.Printf("✅ Payment settlement successful!\n")
	fmt.Printf("   Transaction: %s\n", settleResp.Transaction)
	fmt.Printf("   Network: %s\n", settleResp.Network)
	fmt.Printf("   Payer: %s\n", settleResp.Payer)

	return nil
}

func main() {
	fmt.Println("=== X402 Payer Demo ===")

	// Create payer
	payer := NewPayer()

	// Check balance
	payer.account.PrintAccountInfo("payer")

	// Get payee address (for demo, use the test payee account)
	payeeAddress := GetPayeeWalletAddress()

	// Payment details
	// amount := "1000000000000000000" // 1 Token (assuming 18 decimals)
	amount := "1000000" // 1 Token (assuming 6 decimals)
	resource := "https://api.example.com/premium-content"
	description := "Premium content access"

	fmt.Printf("\nMaking payment:\n")
	fmt.Printf("From: %s\n", payer.account.Address.Hex())
	fmt.Printf("To: %s\n", payeeAddress)
	fmt.Printf("Amount: %s tokens\n", amount)
	fmt.Printf("Resource: %s\n", resource)
	fmt.Printf("Description: %s\n", description)
	fmt.Println()

	// Make payment
	if err := payer.MakePayment(payeeAddress, amount, resource, description); err != nil {
		log.Fatalf("Payment failed: %v", err)
	}

	fmt.Println("\n=== Payment Process Complete ===")

	// Check final balance
	fmt.Println("\nFinal payer balance:")
	payer.account.PrintAccountInfo("payer")
}
