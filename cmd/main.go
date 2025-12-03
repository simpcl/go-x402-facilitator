package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/x402/go-x402-facilitator/internal/api"
	"github.com/x402/go-x402-facilitator/internal/config"
	"github.com/x402/go-x402-facilitator/internal/facilitator"
)

var (
	configPath = flag.String("config", "", "Path to configuration file")
	version    = flag.Bool("version", false, "Show version information")
)

const (
	AppName    = "x402-facilitator"
	AppVersion = "1.0.0"
	AppDesc    = "Production-ready X402 payment facilitator service"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s v%s - %s\n", AppName, AppVersion, AppDesc)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Initialize logger
	setupLogger(cfg)

	log.Info().
		Str("version", AppVersion).
		Msg("Starting X402 Facilitator")

	// Create facilitator instance
	f, err := facilitator.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create facilitator")
	}
	defer f.Close()

	log.Info().
		Int("client_count", f.GetClientCount()).
		Msg("Facilitator initialized successfully")

	// Create API server
	server := api.NewServer(cfg, f)

	// Start metrics server if enabled
	if err := server.StartMetricsServer(); err != nil {
		log.Warn().Err(err).Msg("Failed to start metrics server")
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			log.Error().Err(err).Msg("Server failed to start")
			cancel()
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		log.Info().Msg("Received shutdown signal")
	case <-ctx.Done():
		log.Info().Msg("Context cancelled, shutting down")
	}

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	log.Info().Msg("Shutting down gracefully...")

	if err := server.Stop(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Error during server shutdown")
		os.Exit(1)
	}

	log.Info().Msg("Shutdown completed successfully")
}

// setupLogger configures the global logger
func setupLogger(cfg *config.Config) {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.Monitoring.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure output format
	if cfg.Monitoring.LogFormat == "console" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		log.Logger = log.With().Timestamp().Logger()
	}

	// Add default context fields
	log.Logger = log.Logger.With().
		Str("service", AppName).
		Str("version", AppVersion).
		Logger()
}