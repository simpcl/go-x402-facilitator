package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	// Blockchain Configuration
	BNBTestnetRPC    string
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

	// API Configuration
	BaseURL string
}

func LoadConfig() *Config {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	chainID, _ := strconv.ParseInt(os.Getenv("CHAIN_ID"), 10, 64)

	return &Config{
		BNBTestnetRPC:         getEnv("BNB_TESTNET_RPC", "https://data-seed-prebsc-1-s1.bnbchain.org:8545"),
		ChainID:               chainID,
		USDXTokenAddress:      getEnv("NEXT_PUBLIC_USDX_TOKEN_ADDRESS", "0xcfFA309a5Fb3ac7419eBC8Ba4a6063Ff2a7585F5"),
		AlphaPrivateKey:       getEnv("FACILITATOR_ALPHA_PRIVATE_KEY", ""),
		BetaPrivateKey:        getEnv("FACILITATOR_BETA_PRIVATE_KEY", ""),
		GammaPrivateKey:       getEnv("FACILITATOR_GAMMA_PRIVATE_KEY", ""),
		SettlePrivateKey:      getEnv("FACILITATOR_SETTLE_PRIVATE_KEY", ""),
		MerchantWalletAddress: getEnv("MERCHANT_WALLET_ADDRESS", "0x183052a3526d2ebd0f8dd7a90bed2943e0126795"),
		Port:                  getEnv("PORT", "8080"),
		Host:                  getEnv("HOST", "localhost"),
		BaseURL:               getEnv("NEXT_PUBLIC_BASE_URL", "http://localhost:8080"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
