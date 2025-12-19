package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Facilitator FacilitatorConfig `mapstructure:"facilitator"`
	Auth        AuthConfig        `mapstructure:"auth"`
	Monitoring  MonitoringConfig  `mapstructure:"monitoring"`
	Supported   SupportedConfig   `mapstructure:"supported"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Host          string        `mapstructure:"host"`
	Port          int           `mapstructure:"port"`
	ReadTimeout   time.Duration `mapstructure:"read_timeout"`
	WriteTimeout  time.Duration `mapstructure:"write_timeout"`
	IdleTimeout   time.Duration `mapstructure:"idle_timeout"`
	ResourcesFile string        `mapstructure:"resources_file"`
}

// EthereumConfig represents Ethereum client configuration
type FacilitatorConfig struct {
	DefaultChainNetwork  string `mapstructure:"default_chain_network"`
	DefaultChainRPC      string `mapstructure:"default_chain_rpc"`
	DefaultChainID       uint64 `mapstructure:"default_chain_id"`
	DefaultTokenAddress  string `mapstructure:"default_token_address"`
	DefaultTokenName     string `mapstructure:"default_token_name"`
	DefaultTokenVersion  string `mapstructure:"default_token_version"`
	DefaultTokenDecimals int64  `mapstructure:"default_token_decimals"`
	PrivateKey           string `mapstructure:"private_key"`
	GasLimit             uint64 `mapstructure:"gas_limit"`
	GasPrice             string `mapstructure:"gas_price"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	APIKeys     []string `mapstructure:"api_keys"`
	JWTSecret   string   `mapstructure:"jwt_secret"`
	RequireAuth bool     `mapstructure:"require_auth"`
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
	Schemes        []string          `mapstructure:"schemes"`
	Networks       []string          `mapstructure:"networks"`
	ChainIds       map[string]uint64 `mapstructure:"chain_ids"`
	ChainRPCs      map[string]string `mapstructure:"chain_rpcs"`
	TokenContracts map[string]string `mapstructure:"token_contracts"`
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
	viper.SetDefault("server.resources_file", "resources.json")

	// Ethereum defaults
	viper.SetDefault("facilitator.default_chain_network", "localhost")
	viper.SetDefault("facilitator.default_chain_rpc", "http://127.0.0.1:8545")
	viper.SetDefault("facilitator.default_chain_id", 1337)
	viper.SetDefault("facilitator.default_token_address", "")
	viper.SetDefault("facilitator.default_token_name", "GenericToken")
	viper.SetDefault("facilitator.default_token_version", "1")
	viper.SetDefault("facilitator.default_token_decimals", 6)
	viper.SetDefault("facilitator.private_key", "")
	viper.SetDefault("facilitator.gas_limit", 100000)
	viper.SetDefault("facilitator.gas_price", "")

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
		"localhost",
	})
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

func (c *Config) GetSupportedSchemes() []string {
	if len(c.Supported.Schemes) > 0 {
		return c.Supported.Schemes
	}
	return []string{
		"exact",
	}
}

// GetSupportedNetworks returns list of supported networks
func (c *Config) GetSupportedNetworks() []string {
	if len(c.Supported.Networks) > 0 {
		return c.Supported.Networks
	}
	return []string{}
}

// GetTokenAddress returns Token contract address for the given network
func (c *Config) GetTokenAddress(network string) (string, error) {
	address, exists := c.Supported.TokenContracts[network]
	if !exists {
		return "", fmt.Errorf("network %s not supported", network)
	}
	return address, nil
}

// GetChainID returns the chain ID for the given network
func (c *Config) GetChainID(network string) (uint64, error) {
	chainID, exists := c.Supported.ChainIds[network]
	if !exists {
		return 0, fmt.Errorf("network %s not supported", network)
	}
	return chainID, nil
}

func (c *Config) GetChainRPC(network string) (string, error) {
	rpcURL, exists := c.Supported.ChainRPCs[network]
	if !exists {
		return "", fmt.Errorf("network %s not supported", network)
	}
	return rpcURL, nil
}

func (c *Config) Show() {
	fmt.Println("Config:")
	fmt.Printf("  Server: %+v\n", c.Server)
	fmt.Printf("  Auth: %+v\n", c.Auth)
	fmt.Printf("  Monitoring: %+v\n", c.Monitoring)
	fmt.Printf("  Supported: %+v\n", c.Supported)
}
