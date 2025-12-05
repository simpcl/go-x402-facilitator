package eip712simple

import (
	"fmt"
	"math/big"
	"strings"

	// "github.com/ethereum/go-ethereum/accounts"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/rs/zerolog/log"
)

// TypedDataDomain represents the domain in EIP-712 typed data
type TypedDataDomain struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	ChainID           *big.Int `json:"chainId"`
	VerifyingContract string   `json:"verifyingContract"`
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

// // RecoverAddress recovers the signing address from EIP-712 typed data
// func RecoverAddress(typedData *TypedData, signatureHex string) (common.Address, error) {
// 	signature, err := hexutil.Decode(signatureHex)
// 	if err != nil {
// 		log.Error().Err(err).Msgf("Failed to decode signatureHex: %s", signatureHex)
// 		return common.Address{}, err
// 	}

// 	typedDataHash, err := HashTypedData(typedData)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to hash typedData")
// 		return common.Address{}, err
// 	}

// 	recoveredAddr, err := crypto.SigToPub(typedDataHash[:], signature)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to sig to pub")
// 		return common.Address{}, err
// 	}

// 	return crypto.PubkeyToAddress(*recoveredAddr), nil
// }

// // HashTypedData creates the hash of EIP-712 typed data
// func HashTypedData(typedData *TypedData) (common.Hash, error) {
// 	domainSeparator, err := typedData.HashDomain()
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	typeHash, err := typedData.HashStruct()
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	return crypto.Keccak256Hash(
// 		append([]byte{0x19, 0x01}, append(domainSeparator[:], typeHash[:]...)...),
// 	), nil
// }

// func HashTypedDataBytes(typedData *TypedData) ([]byte, error) {
// 	fullHash, err := HashTypedData(typedData)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return fullHash.Bytes(), nil
// }

// func HashTypedDataBytesByEthAccount(typedData *TypedData) ([]byte, error) {
// 	digest, err := typedData.HashStruct()
// 	if err != nil {
// 		return nil, err
// 	}

// 	domainSeparator, err := typedData.HashDomain()
// 	if err != nil {
// 		return nil, err
// 	}

// 	fullHash := accounts.TextHash(append(
// 		append([]byte("\x19\x01"), domainSeparator...),
// 		digest...,
// 	))
// 	return fullHash, nil
// }

func (td *TypedData) HashDomain() ([]byte, error) {
	domainData := []string{
		td.Domain.Name,
		td.Domain.Version,
		td.Domain.ChainID.String(),
		td.Domain.VerifyingContract,
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
