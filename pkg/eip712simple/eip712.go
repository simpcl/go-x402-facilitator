package eip712simple

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TypedDataDomain represents the domain in EIP-712 typed data
type TypedDataDomain struct {
	Name              string         `json:"name"`
	Version           string         `json:"version"`
	ChainId           uint64         `json:"chainId"`
	VerifyingContract common.Address `json:"verifyingContract"`
}

// TypedDataField represents a field in EIP-712 typed data
type TypedDataField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Types map[string][]TypedDataField

type TypedDataMessage map[string]interface{}

// TypedData represents EIP-712 typed data structure
type TypedData struct {
	Types       map[string][]TypedDataField `json:"types"`
	PrimaryType string                      `json:"primaryType"`
	Domain      TypedDataDomain             `json:"domain"`
	Message     map[string]interface{}      `json:"message"`
}

func (td *TypedData) HashDomain() ([]byte, error) {
	domainData := []string{
		td.Domain.Name,
		td.Domain.Version,
		fmt.Sprintf("%d", td.Domain.ChainId),
		td.Domain.VerifyingContract.String(),
	}

	hash := crypto.Keccak256Hash([]byte(strings.Join(domainData, "")))
	return hash.Bytes(), nil
}

func (td *TypedData) HashStruct() ([]byte, error) {
	data := []byte(td.PrimaryType)
	for _, field := range td.Types[td.PrimaryType] {
		if value, exists := td.Message[field.Name]; exists {
			data = append(data, []byte(fmt.Sprintf("%v", value))...)
		}
	}
	hash := crypto.Keccak256Hash(data)
	return hash.Bytes(), nil
}
