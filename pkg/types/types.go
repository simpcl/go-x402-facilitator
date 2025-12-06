package types

import (
	"math/big"

	"github.com/rs/zerolog/log"
)

// PaymentPayload represents the signed payment payload sent by the client
type PaymentPayload struct {
	X402Version int         `json:"x402Version"`
	Scheme      string      `json:"scheme"`
	Network     string      `json:"network"`
	Payload     interface{} `json:"payload"`
}

// ExactEVMPayload represents the specific payload structure for exact scheme on EVM
type ExactEVMPayload struct {
	Signature     string        `json:"signature"`
	Authorization Authorization `json:"authorization"`
}

// Authorization represents the transfer authorization details
type Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// PaymentRequirements represents the payment requirements from the resource server
type PaymentRequirements struct {
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	MaxAmountRequired string                 `json:"maxAmountRequired"`
	Resource          string                 `json:"resource"`
	Description       string                 `json:"description"`
	MimeType          string                 `json:"mimeType"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
	Asset             string                 `json:"asset"`
	Extra             map[string]interface{} `json:"extra,omitempty"`
}

// VerifyRequest represents the request body for /verify endpoint
type VerifyRequest struct {
	PaymentPayload      PaymentPayload      `json:"paymentPayload"`
	PaymentRequirements PaymentRequirements `json:"paymentRequirements"`
}

// VerifyResponse represents the response from /verify endpoint
type VerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason,omitempty"`
	Payer         string `json:"payer"`
}

// SettleResponse represents the response from /settle endpoint
type SettleResponse struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason,omitempty"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer"`
}

// SupportedKind represents a supported payment scheme and network combination
type SupportedKind struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`
	Network     string `json:"network"`
}

// SupportedResponse represents the response from /supported endpoint
type SupportedResponse struct {
	X402Version int             `json:"x402Version"`
	Kinds       []SupportedKind `json:"kinds"`
}

// DiscoveryItem represents an item in the discovery response
type DiscoveryItem struct {
	Resource    string                `json:"resource"`
	Type        string                `json:"type"`
	X402Version int                   `json:"x402Version"`
	Accepts     []PaymentRequirements `json:"accepts"`
	LastUpdated int64                 `json:"lastUpdated"`
}

// DiscoveryResponse represents the response from /discovery/resources endpoint
type DiscoveryResponse struct {
	X402Version int             `json:"x402Version"`
	Items       []DiscoveryItem `json:"items"`
}

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// Signature represents a parsed Ethereum signature
type Signature struct {
	V *big.Int `json:"v"`
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

func (sig *Signature) ToEthereumSignature() []byte {
	v := sig.V.Uint64()
	if v == 0 || v == 1 {
		log.Info().Msgf("Adjusted v from %d to %d", v, v+27)
		v = v + 27
	}

	var signature []byte
	signature = append(signature, sig.R.Bytes()...)
	signature = append(signature, sig.S.Bytes()...)
	signature = append(signature, byte(v))
	return signature
}
