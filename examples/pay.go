package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/agent-guide/go-x402-facilitator/pkg/client"
	"github.com/agent-guide/go-x402-facilitator/pkg/utils"

	"github.com/ethereum/go-ethereum/crypto"
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
	account *utils.Account
}

// NewPayer creates a new payer instance
func NewPayer() *Payer {
	privateKey := os.Getenv("PAYER_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatalln("ERROR: PAYER_PRIVATE_KEY environment variable is not set")
	}

	account, err := utils.NewAccountWithPrivateKey(ChainRPC, TokenContract, privateKey)
	if err != nil {
		log.Fatalf("ERROR: failed to create payer account: %v", err)
	}
	return &Payer{account: account}
}

// MakePayment makes a payment to the payee
func (b *Payer) MakePayment(sellerAddress string, amount string, resource string, description string) error {
	fmt.Println("=== Starting X402 Payment Process ===")
	fmt.Printf("\nMaking payment:\n")
	fmt.Printf("From: %s\n", b.account.WalletAddress.Hex())
	fmt.Printf("To: %s\n", sellerAddress)
	fmt.Printf("Amount: %s tokens\n", amount)
	fmt.Printf("Resource: %s\n", resource)
	fmt.Printf("Description: %s\n", description)
	fmt.Println()

	fmt.Println("Creating payment requirements...")
	requirements := client.CreatePaymentRequirements(
		"exact",
		ChainNetwork,
		sellerAddress,
		amount,
		"ERC20",
		TokenContract,
		resource,
		description,
		TokenName,
		TokenVersion,
	)

	fmt.Println("Creating payment payload...")
	var validDuration int64 = 300
	now := time.Now().Unix()
	validAfter := now - 600000
	validBefore := now + validDuration
	// Generate nonce
	nonce := fmt.Sprintf(
		"0x%x",
		crypto.Keccak256Hash([]byte(fmt.Sprintf("%d-%s-%s", now, b.account.WalletAddress.Hex(), requirements.PayTo))).Hex(),
	)
	fmt.Printf("Nonce: %s\n", nonce)

	payload, err := client.CreatePaymentPayload(
		requirements,
		b.account.PrivateKey,
		validAfter,
		validBefore,
		ChainID,
		nonce,
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
	payer.account.PrintAccountInfo("Payer")

	// Get payee address (for demo, use the test payee account)
	payeeAddress := GetPayeeWalletAddress()

	// Payment details
	// amount := "1000000000000000000" // 1 Token (assuming 18 decimals)
	amount := "10000000" // 1 Token (assuming 6 decimals)
	resource := "https://api.example.com/premium-content"
	description := "Premium content access"

	// Make payment
	if err := payer.MakePayment(payeeAddress, amount, resource, description); err != nil {
		log.Fatalf("Payment failed: %v", err)
	}

	fmt.Println("\n=== Payment Process Complete ===")

	// Check final balance
	payer.account.PrintAccountInfo("Payer")
}
