package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server       ServerConfig       `mapstructure:"server"`
	Ethereum     EthereumConfig     `mapstructure:"ethereum"`
	Auth         AuthConfig         `mapstructure:"auth"`
	Monitoring   MonitoringConfig   `mapstructure:"monitoring"`
	USDCContract map[string]string  `mapstructure:"usdc_contract"`
	Supported    SupportedConfig    `mapstructure:"supported"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

// EthereumConfig represents Ethereum client configuration
type EthereumConfig struct {
	DefaultRPCURL string            `mapstructure:"default_rpc_url"`
	ChainConfigs  map[string]string `mapstructure:"chain_configs"`
	PrivateKey    string            `mapstructure:"private_key"`
	GasLimit      uint64            `mapstructure:"gas_limit"`
	GasPrice      string            `mapstructure:"gas_price"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	APIKeys    []string `mapstructure:"api_keys"`
	JWTSecret  string   `mapstructure:"jwt_secret"`
	RequireAuth bool    `mapstructure:"require_auth"`
}

// MonitoringConfig represents monitoring and observability configuration
type MonitoringConfig struct {
	MetricsEnabled bool   `mapstructure:"metrics_enabled"`
	MetricsPort    int    `mapstructure:"metrics_port"`
	LogLevel       string `mapstructure:"log_level"`
	LogFormat      string `mapstructure:"log_format"`
}

// SupportedConfig represents supported schemes and networks
type SupportedConfig struct {
	Schemes  []string          `mapstructure:"schemes"`
	Networks []string          `mapstructure:"networks"`
	Chains   map[string]string `mapstructure:"chains"`
}

// LoadConfig loads configuration from file and environment
func LoadConfig(configPath string) (*Config, error) {
	if configPath != "" {
		// If specific config file is provided, use it directly
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/x402-facilitator")
		viper.AddConfigPath("$HOME/.x402-facilitator")
	}

	// Set environment variable prefix
	viper.SetEnvPrefix("X402")
	viper.AutomaticEnv()

	// Set environment variable key replacer to handle underscores
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults and environment
			fmt.Println("Config file not found, using defaults and environment variables")
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")

	// Ethereum defaults
	viper.SetDefault("ethereum.default_rpc_url", "https://eth-mainnet.alchemyapi.io/v2/your-api-key")
	viper.SetDefault("ethereum.gas_limit", 100000)
	viper.SetDefault("ethereum.gas_price", "")

	// Auth defaults
	viper.SetDefault("auth.enabled", true)
	viper.SetDefault("auth.require_auth", false)
	viper.SetDefault("auth.jwt_secret", "change-this-secret-key")

	// Monitoring defaults
	viper.SetDefault("monitoring.metrics_enabled", true)
	viper.SetDefault("monitoring.metrics_port", 9090)
	viper.SetDefault("monitoring.log_level", "info")
	viper.SetDefault("monitoring.log_format", "json")

	// Supported defaults
	viper.SetDefault("supported.schemes", []string{"exact"})
	viper.SetDefault("supported.networks", []string{
		"ethereum-sepolia",
		"ethereum",
		"base-sepolia",
		"base",
		"avalanche-fuji",
		"avalanche",
	})

	// USDC Contract addresses
	viper.SetDefault("usdc_contract.ethereum-sepolia", "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238")
	viper.SetDefault("usdc_contract.ethereum", "0xA0b86a33E6417c5C2c0a9b0B7F8e0B7e8b4a0c8e")
	viper.SetDefault("usdc_contract.base-sepolia", "0x036CbD53842c5426634e7929541eC2318f3dCF7e")
	viper.SetDefault("usdc_contract.base", "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531770b923")
	viper.SetDefault("usdc_contract.avalanche-fuji", "0x5425890298aedC1c239A4317bb48d42A35f0A3C4")
	viper.SetDefault("usdc_contract.avalanche", "0xB97EF9Ef8734C71904D8002F8b6Bc66Da9A84873")
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate server configuration
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	// Validate auth configuration
	if config.Auth.Enabled && len(config.Auth.APIKeys) == 0 && config.Auth.RequireAuth {
		return fmt.Errorf("authentication enabled but no API keys configured")
	}

	// Validate monitoring configuration
	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLogLevels[config.Monitoring.LogLevel] {
		return fmt.Errorf("invalid log level: %s", config.Monitoring.LogLevel)
	}

	return nil
}

// GetSupportedNetworks returns list of supported networks
func (c *Config) GetSupportedNetworks() []string {
	if len(c.Supported.Networks) > 0 {
		return c.Supported.Networks
	}
	return []string{
		"ethereum-sepolia",
		"ethereum",
		"base-sepolia",
		"base",
		"avalanche-fuji",
		"avalanche",
	}
}

// GetUSDCAddress returns USDC contract address for the given network
func (c *Config) GetUSDCAddress(network string) string {
	if address, exists := c.USDCContract[network]; exists {
		return address
	}
	return ""
}