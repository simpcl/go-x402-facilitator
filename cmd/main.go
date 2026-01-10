package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agent-guide/go-x402-facilitator/internal/api"
	"github.com/agent-guide/go-x402-facilitator/internal/config"
	"github.com/agent-guide/go-x402-facilitator/internal/facilitator"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configPath = flag.String("config", "", "Path to configuration env file ('.env' can be load automatically)")
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
	cfg.Show()

	// Initialize logger
	setupLogger(cfg)

	log.Info().
		Str("version", AppVersion).
		Msg("Starting X402 Facilitator")

	// Create facilitator instance
	f, err := facilitator.New(&cfg.Facilitator)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create facilitator")
	}
	defer f.Close()

	log.Info().
		Msg("Facilitator initialized successfully")

	// Create API server
	server := api.NewServer(cfg, f)

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
	level, err := zerolog.ParseLevel(cfg.Server.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure output format
	if cfg.Server.LogFormat == "console" {
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
