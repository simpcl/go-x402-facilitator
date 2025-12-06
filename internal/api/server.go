package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/rs/zerolog/log"
	"github.com/x402/go-x402-facilitator/internal/config"
	"github.com/x402/go-x402-facilitator/internal/facilitator"
	"github.com/x402/go-x402-facilitator/internal/middleware"
)

// Server represents the HTTP server
type Server struct {
	config      *config.Config
	facilitator *facilitator.Facilitator
	httpServer  *http.Server
	handler     *Handler
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config, f *facilitator.Facilitator) *Server {
	return &Server{
		config:      cfg,
		facilitator: f,
		handler:     NewHandler(f),
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Set Gin mode
	if s.config.Monitoring.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	router := gin.New()

	// Add middleware
	s.setupMiddleware(router)

	// Register routes
	s.handler.RegisterRoutes(router)

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler:      router,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}

	log.Info().
		Str("address", s.httpServer.Addr).
		Msg("Starting HTTP server")

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Stop stops the HTTP server gracefully
func (s *Server) Stop(ctx context.Context) error {
	log.Info().Msg("Shutting down HTTP server")

	if s.httpServer == nil {
		return nil
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	log.Info().Msg("HTTP server stopped successfully")
	return nil
}

// setupMiddleware configures the middleware for the Gin router
func (s *Server) setupMiddleware(router *gin.Engine) {
	// Add logging middleware
	router.Use(gin.Logger())

	// Add recovery middleware
	router.Use(gin.Recovery())

	// Add CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		Debug:          s.config.Monitoring.LogLevel == "debug",
	})
	router.Use(corsMiddleware(c))

	// Add authentication middleware if enabled
	if s.config.Auth.Enabled && s.config.Auth.RequireAuth {
		router.Use(middleware.AuthMiddleware(s.config.Auth))
	}

	// Add metrics middleware if enabled
	if s.config.Monitoring.MetricsEnabled {
		router.Use(middleware.MetricsMiddleware())
	}

	// Add request ID middleware
	router.Use(middleware.RequestIDMiddleware())
}

// StartMetricsServer starts the metrics server
func (s *Server) StartMetricsServer() error {
	if !s.config.Monitoring.MetricsEnabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	metricsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Monitoring.MetricsPort),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Info().
		Int("port", s.config.Monitoring.MetricsPort).
		Msg("Starting metrics server")

	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Failed to start metrics server")
		}
	}()

	return nil
}

// corsMiddleware converts cors.Cors to gin middleware
func corsMiddleware(c *cors.Cors) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		c.HandlerFunc(ctx.Writer, ctx.Request)
		ctx.Next()
	}
}
