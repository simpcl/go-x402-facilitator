package api

import (
	"context"
	"fmt"
	"net/http"

	"go-x402-facilitator/internal/config"
	"go-x402-facilitator/internal/facilitator"
	"go-x402-facilitator/internal/middleware"

	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"github.com/rs/zerolog/log"
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
	if s.config.Server.LogLevel == "debug" {
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
		Debug:          s.config.Server.LogLevel == "debug",
	})
	router.Use(corsMiddleware(c))

	// Add request ID middleware
	router.Use(middleware.RequestIDMiddleware())
}

// corsMiddleware converts cors.Cors to gin middleware
func corsMiddleware(c *cors.Cors) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		c.HandlerFunc(ctx.Writer, ctx.Request)
		ctx.Next()
	}
}
