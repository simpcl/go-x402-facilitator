package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config represents the application configuration
type Config struct {
	Server      ServerConfig
	Facilitator FacilitatorConfig
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	LogLevel     string
	LogFormat    string
}

// FacilitatorConfig represents facilitator configuration
type FacilitatorConfig struct {
	Network         string
	ChainRPC        string
	ChainID         uint64
	TokenAddress    string
	TokenName       string
	TokenVersion    string
	TokenDecimals   int64
	PrivateKey      string
	GasLimit        uint64
	GasPrice        string
	SupportedScheme string
}

// LoadConfig loads configuration from .env file
func LoadConfig(configPath string) (*Config, error) {
	// Load .env file using godotenv
	envFile := ".env"
	if configPath != "" {
		envFile = configPath
	}

	// Load .env file (not required if using environment variables)
	if err := godotenv.Load(envFile); err != nil {
		// .env file not found is not an error, we'll use environment variables
		fmt.Printf("Warning: .env file not found (%s), using environment variables only\n", envFile)
	}

	cfg := &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvAsInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvAsDuration("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvAsDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvAsDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
			LogLevel:     getEnv("SERVER_LOG_LEVEL", "info"),
			LogFormat:    getEnv("SERVER_LOG_FORMAT", "json"),
		},
		Facilitator: FacilitatorConfig{
			Network:         getEnv("FACILITATOR_NETWORK", "localhost"),
			ChainRPC:        getEnv("FACILITATOR_CHAIN_RPC", "http://127.0.0.1:8545"),
			ChainID:         getEnvAsUint64("FACILITATOR_CHAIN_ID", 1337),
			TokenAddress:    getEnv("FACILITATOR_TOKEN_ADDRESS", ""),
			TokenName:       getEnv("FACILITATOR_TOKEN_NAME", "MyToken"),
			TokenVersion:    getEnv("FACILITATOR_TOKEN_VERSION", "1"),
			TokenDecimals:   getEnvAsInt64("FACILITATOR_TOKEN_DECIMALS", 6),
			PrivateKey:      getEnv("FACILITATOR_PRIVATE_KEY", ""),
			GasLimit:        getEnvAsUint64("FACILITATOR_GAS_LIMIT", 100000),
			GasPrice:        getEnv("FACILITATOR_GAS_PRICE", ""),
			SupportedScheme: getEnv("FACILITATOR_SUPPORTED_SCHEME", "exact"),
		},
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate server configuration
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	// Validate facilitator configuration
	if config.Facilitator.PrivateKey == "" {
		return fmt.Errorf("FACILITATOR_PRIVATE_KEY is required")
	}

	// Validate server log level configuration
	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLogLevels[config.Server.LogLevel] {
		return fmt.Errorf("invalid log level: %s", config.Server.LogLevel)
	}

	return nil
}

// Show displays the configuration (without sensitive data)
func (c *Config) Show() {
	fmt.Println("Config:")
	fmt.Printf("  Server: Host=%s, Port=%d, LogLevel=%s, LogFormat=%s\n",
		c.Server.Host, c.Server.Port, c.Server.LogLevel, c.Server.LogFormat)
	fmt.Printf("  Facilitator: Network=%s, ChainID=%d, ChainRPC=%s\n",
		c.Facilitator.Network, c.Facilitator.ChainID, c.Facilitator.ChainRPC)
}

// Helper functions for environment variable parsing

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsUint64(key string, defaultValue uint64) uint64 {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseUint(valueStr, 10, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	duration, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return duration
}
