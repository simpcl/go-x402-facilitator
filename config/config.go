package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	// Blockchain Configuration
	BlockchainRPC    string
	ChainID          int64
	USDXTokenAddress string

	// Facilitator Private Keys
	AlphaPrivateKey  string
	BetaPrivateKey   string
	GammaPrivateKey  string
	SettlePrivateKey string

	// Merchant Configuration
	MerchantWalletAddress string

	// Server Configuration
	Port string
	Host string
}

func LoadConfig() *Config {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	chainID, _ := strconv.ParseInt(os.Getenv("BLOCKCHAIN_ID"), 10, 64)

	return &Config{
		BlockchainRPC:         getEnv("BLOCKCHAIN_RPC", "http://127.0.0.1:8545"),
		ChainID:               chainID,
		USDXTokenAddress:      getEnv("NEXT_PUBLIC_USDX_TOKEN_ADDRESS", "0xcfFA309a5Fb3ac7419eBC8Ba4a6063Ff2a7585F5"),
		AlphaPrivateKey:       getEnv("FACILITATOR_ALPHA_PRIVATE_KEY", ""),
		BetaPrivateKey:        getEnv("FACILITATOR_BETA_PRIVATE_KEY", ""),
		GammaPrivateKey:       getEnv("FACILITATOR_GAMMA_PRIVATE_KEY", ""),
		SettlePrivateKey:      getEnv("FACILITATOR_SETTLE_PRIVATE_KEY", ""),
		MerchantWalletAddress: getEnv("MERCHANT_WALLET_ADDRESS", "0x183052a3526d2ebd0f8dd7a90bed2943e0126795"),
		Port:                  getEnv("PORT", "8080"),
		Host:                  getEnv("HOST", "localhost"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (cfg *Config) GetChainName() string {
	switch cfg.ChainID {
	case 1:
		return "Ethereum Mainnet"
	case 56:
		return "BNB Smart Chain Mainnet"
	case 97:
		return "BNB Smart Chain Testnet"
	case 137:
		return "Polygon Mainnet"
	case 80001:
		return "Mumbai Testnet"
	case 42161:
		return "Arbitrum One"
	case 421613:
		return "Arbitrum Goerli"
	case 10:
		return "Optimism"
	case 69:
		return "Optimism Kovan"
	case 1337:
		return "Local Development Chain"
	default:
		return "Unknown Chain"
	}
}
func (cfg *Config) GetNativeCurrencySymbol() string {
	switch cfg.ChainID {
	case 1, 5, 11155111: // Ethereum mainnet, Goerli, Sepolia
		return "ETH"
	case 56, 97: // BSC mainnet, testnet
		return "BNB"
	case 137, 80001: // Polygon mainnet, Mumbai
		return "MATIC"
	case 42161, 421613: // Arbitrum
		return "ETH"
	case 10, 69: // Optimism
		return "ETH"
	case 1337: // Local development
		return "ETH"
	default:
		return "ETH"
	}
}

func (cfg *Config) GetBlockExplorerURL() string {
	switch cfg.ChainID {
	case 1:
		return "https://etherscan.io"
	case 5:
		return "https://goerli.etherscan.io"
	case 11155111:
		return "https://sepolia.etherscan.io"
	case 56:
		return "https://bscscan.com"
	case 97:
		return "https://testnet.bscscan.com"
	case 137:
		return "https://polygonscan.com"
	case 80001:
		return "https://mumbai.polygonscan.com"
	case 42161:
		return "https://arbiscan.io"
	case 421613:
		return "https://goerli.arbiscan.io"
	case 10:
		return "https://optimistic.etherscan.io"
	case 69:
		return "https://kovan-optimistic.etherscan.io"
	case 1337:
		return "" // Local development, no block explorer
	default:
		return "" // Unknown chain, return empty
	}
}
func (cfg *Config) GetBlockExplorerURLForChain() string {
	switch cfg.ChainID {
	case 1:
		return "https://etherscan.io"
	case 5:
		return "https://goerli.etherscan.io"
	case 11155111:
		return "https://sepolia.etherscan.io"
	case 56:
		return "https://bscscan.com"
	case 97:
		return "https://testnet.bscscan.com"
	case 137:
		return "https://polygonscan.com"
	case 80001:
		return "https://mumbai.polygonscan.com"
	case 42161:
		return "https://arbiscan.io"
	case 421613:
		return "https://goerli.arbiscan.io"
	case 10:
		return "https://optimistic.etherscan.io"
	case 69:
		return "https://kovan-optimistic.etherscan.io"
	case 1337:
		return "" // Local development, no block explorer
	default:
		return "" // Unknown chain, return empty
	}
}
