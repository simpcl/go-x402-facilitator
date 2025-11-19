package models

import (
	"math/big"
	"time"
)

// Settlement represents a payment settlement
type Settlement struct {
	TxHash              string    `json:"txHash"`
	Amount              string    `json:"amount"`
	To                  string    `json:"to"`
	GasCost             string    `json:"gasCost"`
	Payer               string    `json:"payer"`
	BlockNumber         uint64    `json:"blockNumber"`
	Timestamp           time.Time `json:"timestamp"`
	FacilitatorAddress  string    `json:"facilitatorAddress"`
	FeeBps              int       `json:"feeBps"`
}

// PaymentRequest represents a payment request to facilitator
type PaymentRequest struct {
	Owner     string `json:"owner,omitempty"`
	Value     string `json:"value,omitempty"`
	Deadline  string `json:"deadline,omitempty"`
	V         int    `json:"v,omitempty"`
	R         string `json:"r,omitempty"`
	S         string `json:"s,omitempty"`
	Permit    string `json:"permit,omitempty"`
	Amount    string `json:"amount,omitempty"`
}

// PaymentResponse represents the response from facilitator
type PaymentResponse struct {
	Settled             bool   `json:"settled,omitempty"`
	Paid                bool   `json:"paid,omitempty"`
	TxHash              string `json:"txHash"`
	BlockNumber         uint64 `json:"blockNumber"`
	Facilitator         string `json:"facilitator"`
	FacilitatorAddress  string `json:"facilitatorAddress"`
	Merchant            string `json:"merchant,omitempty"`
	Payer               string `json:"payer,omitempty"`
	Amount              string `json:"amount"`
	FeeBps              int    `json:"feeBps,omitempty"`
	Fee                 string `json:"fee,omitempty"`
	Chain               string `json:"chain,omitempty"`
	Network             string `json:"network,omitempty"`
	GasUsed             string `json:"gasUsed,omitempty"`
	GasCost             string `json:"gasCost"`
	Timestamp           int64  `json:"timestamp"`
	BalanceBefore       string `json:"balanceBefore,omitempty"`
	BalanceAfter        string `json:"balanceAfter,omitempty"`
	Asset               string `json:"asset,omitempty"`
}

// PaymentRequiredResponse represents 402 response with facilitator list
type PaymentRequiredResponse struct {
	Price        string        `json:"price"`
	Asset        string        `json:"asset"`
	Facilitators []Facilitator `json:"facilitators"`
	Secret       string        `json:"secret,omitempty"`
}

// Facilitator represents a facilitator in the list
type Facilitator struct {
	Name      string `json:"name"`
	Fee       string `json:"fee"`
	Endpoint  string `json:"endpoint"`
	Address   string `json:"address,omitempty"`
	Live      bool   `json:"live,omitempty"`
	URL       string `json:"url,omitempty"`
	FeeBps    int    `json:"feeBps,omitempty"`
	Status    string `json:"status,omitempty"`
	Note      string `json:"note,omitempty"`
}

// StatsResponse represents statistics response
type StatsResponse struct {
	Summary       SummaryStats          `json:"summary"`
	Facilitators  []FacilitatorStats    `json:"facilitators"`
	Events        []TransactionEvent    `json:"events"`
}

// SummaryStats represents summary statistics
type SummaryStats struct {
	ActiveFacilitators  int     `json:"activeFacilitators"`
	Requests24h         int     `json:"requests24h"`
	Volume24h           string  `json:"volume24h"`
	AvgFee              string  `json:"avgFee"`
	Uptime              string  `json:"uptime"`
	AvgSettlementTime   string  `json:"avgSettlementTime"`
	MerchantRevenue     string  `json:"merchantRevenue"`
	MerchantAddress     string  `json:"merchantAddress"`
	GasSponsored24h     string  `json:"gasSponsored24h"`
}

// FacilitatorStats represents individual facilitator statistics
type FacilitatorStats struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	StatusTone  string `json:"statusTone"`
	Fee         string `json:"fee"`
	Requests    string `json:"requests"`
	Volume      string `json:"volume"`
	LastTxHash  string `json:"lastTxHash"`
	ExplorerUrl string `json:"explorerUrl"`
	Tags        []string `json:"tags"`
	Uptime      string `json:"uptime"`
}

// TransactionEvent represents a transaction event
type TransactionEvent struct {
	Time        string `json:"time"`
	Facilitator string `json:"facilitator"`
	Amount      string `json:"amount"`
	Route       string `json:"route"`
	Merchant    string `json:"merchant"`
	TxHashShort string `json:"txHashShort"`
	ExplorerUrl string `json:"explorerUrl"`
}

// PermitRequest represents EIP-2612 permit request
type PermitRequest struct {
	Owner    string `json:"owner"`
	Spender  string `json:"spender"`
	Value    string `json:"value"`
	Deadline uint64 `json:"deadline"`
	V        int    `json:"v"`
	R        string `json:"r"`
	S        string `json:"s"`
}

// ERC20Token represents ERC20 token information
type ERC20Token struct {
	Address     string   `json:"address"`
	Name        string   `json:"name"`
	Symbol      string   `json:"symbol"`
	Decimals    uint8    `json:"decimals"`
	TotalSupply *big.Int `json:"totalSupply"`
}

// ContractInteraction represents a generic contract interaction request
type ContractInteraction struct {
	PrivateKey      string `json:"privateKey"`
	TokenAddress    string `json:"tokenAddress"`
	Destination     string `json:"destination"`
	Amount          string `json:"amount"`
	GasLimit        uint64 `json:"gasLimit,omitempty"`
	GasPrice        string `json:"gasPrice,omitempty"`
}

// TransferResponse represents the response from token transfer
type TransferResponse struct {
	Success      bool   `json:"success"`
	TxHash       string `json:"txHash"`
	BlockNumber  uint64 `json:"blockNumber"`
	GasUsed      uint64 `json:"gasUsed"`
	GasCost      string `json:"gasCost"`
	Amount       string `json:"amount"`
	From         string `json:"from"`
	To           string `json:"to"`
	TokenAddress string `json:"tokenAddress"`
	SpentBy      string `json:"spentBy,omitempty"`
	Timestamp    int64  `json:"timestamp,omitempty"`
	Error        string `json:"error,omitempty"`
}

// VerifyRequest represents a verification request payload
type VerifyRequest struct {
	TxHash         string `json:"txHash"`
	ExpectedPayer  string `json:"expectedPayer,omitempty"`
	ExpectedAmount string `json:"expectedAmount,omitempty"`
	TokenAddress   string `json:"tokenAddress,omitempty"`
	ChainID        int64  `json:"chainId,omitempty"`
	RPCURL         string `json:"rpcUrl,omitempty"`
}

// VerifyResponse represents the response from verification
type VerifyResponse struct {
	Valid      bool   `json:"valid"`
	TxHash     string `json:"txHash"`
	Block      uint64 `json:"block,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Amount     string `json:"amount,omitempty"`
	Error      string `json:"error,omitempty"`
	Message    string `json:"message,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}