package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-x402-facilitator/internal/config"
	"go-x402-facilitator/internal/facilitator"
	"go-x402-facilitator/pkg/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// ResourceConfig represents a resource configuration loaded from JSON
type ResourceConfig struct {
	Resource    string                      `json:"resource"`
	Type        string                      `json:"type"`
	X402Version int                         `json:"x402Version"`
	Accepts     []types.PaymentRequirements `json:"accepts"`
	LastUpdated int64                       `json:"lastUpdated"`
	TargetURL   string                      `json:"targetUrl"` // The actual backend URL to proxy to
}

// ResourcesList represents the structure of the resources JSON file
type ResourcesList struct {
	Resources []ResourceConfig `json:"resources"`
}

// Handler contains the API handlers
type ResourceGatewayHandler struct {
	facilitator    *facilitator.Facilitator
	config         *config.Config
	resources      map[string]*ResourceConfig // Map of resource path to config
	resourcesMutex sync.RWMutex
	resourcesFile  string
	lastLoadTime   time.Time
}

// NewHandler creates a new API handler
func NewResourceGatewayHandler(f *facilitator.Facilitator, cfg *config.Config) *ResourceGatewayHandler {
	resourcesFile := cfg.Server.ResourcesFile
	if resourcesFile == "" {
		resourcesFile = "resources.json" // Default path
	}

	handler := &ResourceGatewayHandler{
		facilitator:   f,
		config:        cfg,
		resources:     make(map[string]*ResourceConfig),
		resourcesFile: resourcesFile,
	}

	// Load resources on startup
	if err := handler.loadResources(); err != nil {
		log.Warn().Err(err).Msg("Failed to load resources on startup, will retry on first request")
	}

	return handler
}

// RegisterRoutes registers all API routes
func (h *ResourceGatewayHandler) RegisterRoutes(router *gin.Engine) {
	resources := router.Group("/resources")
	{
		resources.GET("/discover", h.DiscoverResources)
	}
	api := router.Group("/api")
	{
		// Catch-all route for api requests - must be last
		api.Any("/*path", h.HandleResourceRequest)
	}
}

// DiscoverResources handles the /discovery/resources endpoint
func (h *ResourceGatewayHandler) DiscoverResources(c *gin.Context) {
	// Parse query parameters
	resourceType := c.Query("type")
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 20
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Call facilitator
	response, err := h.discoverResources(c.Request.Context(), resourceType, limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("Facilitator discover resources failed")
		c.JSON(http.StatusInternalServerError, types.ErrorResponse{
			Error:   "internal_error",
			Message: "Internal server error during resource discovery",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// loadResources loads resources from the JSON file
func (h *ResourceGatewayHandler) loadResources() error {
	// Check if file exists
	if _, err := os.Stat(h.resourcesFile); os.IsNotExist(err) {
		log.Warn().Str("file", h.resourcesFile).Msg("Resources file not found, using empty resource list")
		return nil
	}

	// Read file
	data, err := os.ReadFile(h.resourcesFile)
	if err != nil {
		return fmt.Errorf("failed to read resources file: %w", err)
	}

	// Parse JSON
	var resourcesList ResourcesList
	if err := json.Unmarshal(data, &resourcesList); err != nil {
		return fmt.Errorf("failed to parse resources JSON: %w", err)
	}

	// Update resources map
	h.resourcesMutex.Lock()
	defer h.resourcesMutex.Unlock()

	h.resources = make(map[string]*ResourceConfig)
	for i := range resourcesList.Resources {
		resource := &resourcesList.Resources[i]
		// Normalize resource path (ensure it starts with /)
		resourcePath := resource.Resource
		if !strings.HasPrefix(resourcePath, "/") {
			resourcePath = "/" + resourcePath
		}
		h.resources[resourcePath] = resource
	}

	h.lastLoadTime = time.Now()
	log.Info().
		Int("count", len(h.resources)).
		Str("file", h.resourcesFile).
		Msg("Resources loaded successfully")

	return nil
}

// reloadResourcesIfNeeded reloads resources if the file has been modified
func (h *ResourceGatewayHandler) reloadResourcesIfNeeded() error {
	// Check if file exists
	info, err := os.Stat(h.resourcesFile)
	if os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to reload
	}

	// Check if file was modified after last load
	if info.ModTime().After(h.lastLoadTime) {
		log.Info().Msg("Resources file modified, reloading...")
		return h.loadResources()
	}

	return nil
}

// findResource finds a resource configuration by path
func (h *ResourceGatewayHandler) findResource(path string) *ResourceConfig {
	h.resourcesMutex.RLock()
	defer h.resourcesMutex.RUnlock()

	// Try exact match first
	if resource, exists := h.resources[path]; exists {
		return resource
	}

	// Try to find longest matching prefix
	var bestMatch *ResourceConfig
	var bestMatchLen int

	for resourcePath, resource := range h.resources {
		if strings.HasPrefix(path, resourcePath) && len(resourcePath) > bestMatchLen {
			bestMatch = resource
			bestMatchLen = len(resourcePath)
		}
	}

	return bestMatch
}

// HandleResourceRequest handles requests to resources
func (h *ResourceGatewayHandler) HandleResourceRequest(c *gin.Context) {
	// Reload resources if needed
	if err := h.reloadResourcesIfNeeded(); err != nil {
		log.Warn().Err(err).Msg("Failed to reload resources")
	}

	// Get the requested path
	requestPath := c.Param("path")
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}

	// Find resource configuration
	resource := h.findResource(requestPath)
	if resource == nil {
		c.JSON(http.StatusNotFound, types.ErrorResponse{
			Error:   "resource_not_found",
			Message: fmt.Sprintf("Resource not found: %s", requestPath),
			Code:    http.StatusNotFound,
		})
		return
	}

	// Check if resource has payment requirements
	if len(resource.Accepts) == 0 {
		// No payment required, proxy directly
		h.proxyRequest(c, resource)
		return
	}

	// Check for X-Payment header
	paymentHeader := c.GetHeader("X-Payment")
	if paymentHeader == "" {
		// No payment provided, return 402 Payment Required
		h.returnPaymentRequired(c, resource)
		return
	}

	// Parse and validate payment
	if err := h.processPayment(c, resource, paymentHeader); err != nil {
		log.Error().Err(err).Msg("Payment processing failed")
		c.JSON(http.StatusPaymentRequired, types.ErrorResponse{
			Error:   "payment_failed",
			Message: err.Error(),
			Code:    http.StatusPaymentRequired,
		})
		return
	}

	// Payment successful, proxy the request
	h.proxyRequest(c, resource)
}

// returnPaymentRequired returns a 402 Payment Required response with payment requirements
func (h *ResourceGatewayHandler) returnPaymentRequired(c *gin.Context, resource *ResourceConfig) {
	// Select the first payment requirement (in production, you might want to select based on client preferences)
	if len(resource.Accepts) == 0 {
		c.JSON(http.StatusInternalServerError, types.ErrorResponse{
			Error:   "internal_error",
			Message: "Resource has no payment requirements configured",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	requirements := resource.Accepts[0]

	// Return 402 with payment requirements
	c.Header("X-Payment-Required", "true")
	c.JSON(http.StatusPaymentRequired, gin.H{
		"error":               "payment_required",
		"message":             "Payment is required to access this resource",
		"code":                http.StatusPaymentRequired,
		"paymentRequirements": requirements,
	})
}

// processPayment processes the X-Payment header and verifies/settles the payment
func (h *ResourceGatewayHandler) processPayment(c *gin.Context, resource *ResourceConfig, paymentHeader string) error {
	// Parse X-Payment header (should be JSON)
	var paymentPayload types.PaymentPayload
	if err := json.Unmarshal([]byte(paymentHeader), &paymentPayload); err != nil {
		return fmt.Errorf("failed to parse X-Payment header: %w", err)
	}

	// Select matching payment requirement
	var requirements *types.PaymentRequirements
	for i := range resource.Accepts {
		req := &resource.Accepts[i]
		if req.Scheme == paymentPayload.Scheme && req.Network == paymentPayload.Network {
			requirements = req
			break
		}
	}

	if requirements == nil {
		return fmt.Errorf("no matching payment requirements found for scheme=%s, network=%s",
			paymentPayload.Scheme, paymentPayload.Network)
	}

	// Create verify request
	verifyReq := types.VerifyRequest{
		PaymentPayload:      paymentPayload,
		PaymentRequirements: *requirements,
	}

	// Verify payment
	ctx := c.Request.Context()
	verifyResp, err := h.facilitator.Verify(ctx, &verifyReq)
	if err != nil {
		return fmt.Errorf("payment verification failed: %w", err)
	}

	if !verifyResp.IsValid {
		return fmt.Errorf("payment is invalid: %s", verifyResp.InvalidReason)
	}

	// Settle payment
	settleResp, err := h.facilitator.Settle(ctx, &verifyReq)
	if err != nil {
		return fmt.Errorf("payment settlement failed: %w", err)
	}

	if !settleResp.Success {
		return fmt.Errorf("payment settlement failed: %s", settleResp.ErrorReason)
	}

	log.Info().
		Str("resource", resource.Resource).
		Str("payer", settleResp.Payer).
		Str("transaction", settleResp.Transaction).
		Msg("Payment processed successfully")

	// Store payment info in context for potential use in proxy
	c.Set("payment_payer", settleResp.Payer)
	c.Set("payment_transaction", settleResp.Transaction)

	return nil
}

// proxyRequest proxies the request to the target URL
func (h *ResourceGatewayHandler) proxyRequest(c *gin.Context, resource *ResourceConfig) {
	if resource.TargetURL == "" {
		c.JSON(http.StatusInternalServerError, types.ErrorResponse{
			Error:   "internal_error",
			Message: "Resource target URL not configured",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	// Parse target URL
	targetURL, err := url.Parse(resource.TargetURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.ErrorResponse{
			Error:   "internal_error",
			Message: fmt.Sprintf("Invalid target URL: %s", err.Error()),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Preserve original path and query
		req.URL.Path = c.Param("path")
		req.URL.RawQuery = c.Request.URL.RawQuery
		// Remove X-Payment header before forwarding
		req.Header.Del("X-Payment")
		// Preserve other headers
		for key, values := range c.Request.Header {
			if key != "X-Payment" {
				req.Header[key] = values
			}
		}
	}

	// Handle errors
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Error().Err(err).Msg("Proxy error")
		rw.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(rw).Encode(types.ErrorResponse{
			Error:   "bad_gateway",
			Message: fmt.Sprintf("Failed to proxy request: %s", err.Error()),
			Code:    http.StatusBadGateway,
		})
	}

	// Serve the request
	proxy.ServeHTTP(c.Writer, c.Request)
}

// DiscoverResources returns discovered resources from loaded configuration
func (h *ResourceGatewayHandler) discoverResources(ctx context.Context, resourceType string, limit, offset int) (*types.DiscoveryResponse, error) {
	// Reload resources if needed
	if err := h.reloadResourcesIfNeeded(); err != nil {
		log.Warn().Err(err).Msg("Failed to reload resources for discovery")
	}

	h.resourcesMutex.RLock()
	defer h.resourcesMutex.RUnlock()

	// Convert resources to discovery items
	var items []types.DiscoveryItem
	for _, resource := range h.resources {
		// Filter by type if specified
		if resourceType != "" && resource.Type != resourceType {
			continue
		}

		items = append(items, types.DiscoveryItem{
			Resource:    resource.Resource,
			Type:        resource.Type,
			X402Version: resource.X402Version,
			Accepts:     resource.Accepts,
			LastUpdated: resource.LastUpdated,
		})
	}

	// Apply pagination
	start := offset
	if start > len(items) {
		start = len(items)
	}

	end := start + limit
	if end > len(items) {
		end = len(items)
	}

	var paginatedItems []types.DiscoveryItem
	if start < len(items) {
		paginatedItems = items[start:end]
	}

	return &types.DiscoveryResponse{
		X402Version: 1,
		Items:       paginatedItems,
	}, nil
}
