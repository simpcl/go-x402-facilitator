package eip712simple

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
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

// Signature represents a parsed Ethereum signature
type Signature struct {
	V *big.Int `json:"v"`
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

// ParseSignature parses an Ethereum signature
func ParseSignature(signatureHex string) (*Signature, error) {
	signature, err := hexutil.Decode(signatureHex)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes long: %d", len(signature))
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := new(big.Int).SetBytes([]byte{signature[64]})

	return &Signature{
		V: v,
		R: r,
		S: s,
	}, nil
}

// RecoverAddress recovers the signing address from EIP-712 typed data
func RecoverAddress(typedData *TypedData, signatureHex string) (common.Address, error) {
	sig, err := ParseSignature(signatureHex)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to parse signature: %s", signatureHex)
		return common.Address{}, err
	}

	v := sig.V.Uint64()

	var signature []byte
	signature = append(signature, sig.R.Bytes()...)
	signature = append(signature, sig.S.Bytes()...)
	signature = append(signature, byte(v))

	// Adjust v to be 27 or 28
	log.Info().Msgf("Adjusted v: %d", v)
	if v == 0 || v == 1 {
		v = v + 27
	}
	if v != 27 && v != 28 {
		return common.Address{}, fmt.Errorf("invalid v value: %d", v)
	}

	typedDataHash, err := HashTypedData(typedData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash typedData")
		return common.Address{}, err
	}

	recoveredAddr, err := crypto.SigToPub(typedDataHash[:], signature)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sig to pub")
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*recoveredAddr), nil
}

// HashTypedData creates the hash of EIP-712 typed data
func HashTypedData(typedData *TypedData) (common.Hash, error) {
	// domainSeparator, err := hashDomainSeparator(&typedData.Domain)
	domainSeparator, err := typedData.hashDomain()
	if err != nil {
		return common.Hash{}, err
	}

	// typeHash, err := hashTypeHash(typedData.Types, typedData.PrimaryType, typedData.Message)
	typeHash, err := typedData.hashStruct()
	if err != nil {
		return common.Hash{}, err
	}

	return crypto.Keccak256Hash(
		append([]byte{0x19, 0x01}, append(domainSeparator[:], typeHash[:]...)...),
	), nil
}

// hashDomainSeparator creates the domain separator hash
// func hashDomainSeparator(domain *TypedDataDomain) (common.Hash, error) {
// 	domainData := []string{
// 		domain.Name,
// 		domain.Version,
// 		domain.ChainID.String(),
// 		domain.VerifyingContract,
// 	}

// 	return crypto.Keccak256Hash([]byte(strings.Join(domainData, ""))), nil
// }

func (td *TypedData) hashDomain() (common.Hash, error) {
	domainData := []string{
		td.Domain.Name,
		td.Domain.Version,
		td.Domain.ChainID.String(),
		td.Domain.VerifyingContract,
	}

	return crypto.Keccak256Hash([]byte(strings.Join(domainData, ""))), nil
}

// hashTypeHash creates the hash for the specific type and message
// func hashTypeHash(types map[string][]TypedDataField, primaryType string, message map[string]interface{}) (common.Hash, error) {
// 	// This is a simplified version - in production, you'd want a more complete implementation
// 	data := []byte(primaryType)
// 	for _, field := range types[primaryType] {
// 		if value, exists := message[field.Name]; exists {
// 			data = append(data, []byte(fmt.Sprintf("%v", value))...)
// 		}
// 	}
// 	return crypto.Keccak256Hash(data), nil
// }

func (td *TypedData) hashStruct() (common.Hash, error) {
	data := []byte(td.PrimaryType)
	for _, field := range td.Types[td.PrimaryType] {
		if value, exists := td.Message[field.Name]; exists {
			data = append(data, []byte(fmt.Sprintf("%v", value))...)
		}
	}
	return crypto.Keccak256Hash(data), nil
}
