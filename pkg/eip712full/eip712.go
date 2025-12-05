package eip712full

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
)

// TypedDataDomain represents the domain in EIP-712 typed data
type TypedDataDomain struct {
	Name              string
	Version           string
	ChainId           uint64
	VerifyingContract common.Address
}

// TypedDataField represents a field in EIP-712 typed data
type TypedDataField struct {
	Name string
	Type string
}

type Types map[string][]TypedDataField

type TypedDataMessage map[string]interface{}

// TypedData represents EIP-712 typed data structure
type TypedData struct {
	Types       Types
	PrimaryType string
	Domain      TypedDataDomain
	Message     TypedDataMessage
}

// RecoverAddress recovers the signing address from EIP-712 typed data
func RecoverAddress(typedData *TypedData, signatureHex string) (common.Address, error) {
	signature, err := hexutil.Decode(signatureHex)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to decode signatureHex: %s", signatureHex)
		return common.Address{}, err
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
	digest, err := typedData.HashStruct()
	if err != nil {
		return common.Hash{}, err
	}

	domainSeparator, err := typedData.HashDomain()
	if err != nil {
		return common.Hash{}, err
	}

	return crypto.Keccak256Hash(
		append(append([]byte("\x19\x01"), domainSeparator...), digest...),
	), nil
}

func (td *TypedData) HashDomain() ([]byte, error) {
	domainTypeHash := crypto.Keccak256Hash([]byte(
		"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
	))

	nameHash := crypto.Keccak256Hash([]byte(td.Domain.Name))
	versionHash := crypto.Keccak256Hash([]byte(td.Domain.Version))
	chainID := big.NewInt(int64(td.Domain.ChainId))

	encoded, err := abi.Arguments{
		{Type: mustType("bytes32")},
		{Type: mustType("bytes32")},
		{Type: mustType("bytes32")},
		{Type: mustType("uint256")},
		{Type: mustType("address")},
	}.Pack(
		domainTypeHash,
		nameHash,
		versionHash,
		chainID,
		td.Domain.VerifyingContract,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack domain: %w", err)
	}

	hash := crypto.Keccak256Hash(encoded)
	return hash.Bytes(), nil
}

func (td *TypedData) HashStruct() ([]byte, error) {
	fields, ok := td.Types[td.PrimaryType]
	if !ok {
		return nil, fmt.Errorf("primary type %s not found in types", td.PrimaryType)
	}

	typeString := td.encodeType(td.PrimaryType)
	typeHash := crypto.Keccak256Hash([]byte(typeString))

	values := make([]interface{}, 0, len(fields)+1)
	values = append(values, typeHash)

	for _, field := range fields {
		value, ok := td.Message[field.Name]
		if !ok {
			return nil, fmt.Errorf("field %s not found in message", field.Name)
		}

		processedValue, err := td.processValue(field.Type, value)
		if err != nil {
			return nil, fmt.Errorf("failed to process field %s: %w", field.Name, err)
		}
		values = append(values, processedValue)
	}

	argTypes := make([]abi.Type, 0, len(fields)+1)
	argTypes = append(argTypes, mustType("bytes32")) // TYPEHASH

	for _, field := range fields {
		argType, err := td.getABIType(field.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to get ABI type for %s: %w", field.Type, err)
		}
		argTypes = append(argTypes, argType)
	}

	args := make(abi.Arguments, len(argTypes))
	for i, t := range argTypes {
		args[i] = abi.Argument{Type: t}
	}

	encoded, err := args.Pack(values...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack struct: %w", err)
	}

	hash := crypto.Keccak256Hash(encoded)
	return hash.Bytes(), nil
}

func (td *TypedData) encodeType(typeName string) string {
	fields, ok := td.Types[typeName]
	if !ok {
		return ""
	}

	result := typeName + "("
	for i, field := range fields {
		if i > 0 {
			result += ","
		}
		result += field.Type + " " + field.Name
	}
	result += ")"

	return result
}

func (td *TypedData) processValue(typeStr string, value interface{}) (interface{}, error) {
	switch typeStr {
	case "address":
		if addr, ok := value.(common.Address); ok {
			return addr, nil
		}
		if str, ok := value.(string); ok {
			return common.HexToAddress(str), nil
		}
		return nil, fmt.Errorf("invalid address value: %v", value)

	case "uint256", "uint8", "uint16", "uint32", "uint64", "uint128":
		if str, ok := value.(string); ok {
			val := new(big.Int)
			val, ok := val.SetString(str, 10)
			if !ok {
				return nil, fmt.Errorf("invalid uint256 value: %s", str)
			}
			return val, nil
		}
		if val, ok := value.(*big.Int); ok {
			return val, nil
		}
		if val, ok := value.(big.Int); ok {
			return &val, nil
		}
		return nil, fmt.Errorf("invalid uint256 value: %v", value)

	case "int256", "int8", "int16", "int32", "int64", "int128":
		if str, ok := value.(string); ok {
			val := new(big.Int)
			val, ok := val.SetString(str, 10)
			if !ok {
				return nil, fmt.Errorf("invalid int256 value: %s", str)
			}
			return val, nil
		}
		if val, ok := value.(*big.Int); ok {
			return val, nil
		}
		return nil, fmt.Errorf("invalid int256 value: %v", value)

	case "bytes32":
		if hash, ok := value.(common.Hash); ok {
			return hash, nil
		}
		if str, ok := value.(string); ok {
			return common.HexToHash(str), nil
		}
		return nil, fmt.Errorf("invalid bytes32 value: %v", value)

	case "bytes":
		if bytes, ok := value.([]byte); ok {
			return bytes, nil
		}
		if str, ok := value.(string); ok {
			return common.Hex2Bytes(str), nil
		}
		return nil, fmt.Errorf("invalid bytes value: %v", value)

	case "string":
		if str, ok := value.(string); ok {
			return crypto.Keccak256Hash([]byte(str)), nil
		}
		return nil, fmt.Errorf("invalid string value: %v", value)

	default:
		if nestedFields, ok := td.Types[typeStr]; ok {
			typeString := td.encodeType(typeStr)
			typeHash := crypto.Keccak256Hash([]byte(typeString))

			if msgMap, ok := value.(TypedDataMessage); ok {
				values := []interface{}{typeHash}
				for _, field := range nestedFields {
					fieldValue, ok := msgMap[field.Name]
					if !ok {
						return nil, fmt.Errorf("field %s not found in nested message", field.Name)
					}
					processedValue, err := td.processValue(field.Type, fieldValue)
					if err != nil {
						return nil, err
					}
					values = append(values, processedValue)
				}

				argTypes := []abi.Type{mustType("bytes32")}
				for _, field := range nestedFields {
					argType, err := td.getABIType(field.Type)
					if err != nil {
						return nil, err
					}
					argTypes = append(argTypes, argType)
				}

				args := make(abi.Arguments, len(argTypes))
				for i, t := range argTypes {
					args[i] = abi.Argument{Type: t}
				}

				encoded, err := args.Pack(values...)
				if err != nil {
					return nil, err
				}

				return crypto.Keccak256Hash(encoded), nil
			}
		}
		return nil, fmt.Errorf("unsupported type: %s", typeStr)
	}
}

func (td *TypedData) getABIType(typeStr string) (abi.Type, error) {
	switch typeStr {
	case "address":
		return mustType("address"), nil
	case "uint256", "uint8", "uint16", "uint32", "uint64", "uint128":
		return mustType("uint256"), nil
	case "int256", "int8", "int16", "int32", "int64", "int128":
		return mustType("int256"), nil
	case "bytes32":
		return mustType("bytes32"), nil
	case "bytes":
		return mustType("bytes"), nil
	case "string":
		return mustType("bytes32"), nil
	default:
		if _, ok := td.Types[typeStr]; ok {
			return mustType("bytes32"), nil
		}
		return abi.Type{}, fmt.Errorf("unknown type: %s", typeStr)
	}
}

func mustType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create type %s: %v", t, err))
	}
	return typ
}
