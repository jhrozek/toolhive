// Package server implements the Virtual MCP Server that aggregates
// multiple backend MCP servers into a unified interface.
//
// The server exposes aggregated capabilities (tools, resources, prompts)
// and routes incoming MCP protocol requests to appropriate backend workloads.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/logger"
	"github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/aggregator"
	"github.com/stacklok/toolhive/pkg/vmcp/discovery"
	"github.com/stacklok/toolhive/pkg/vmcp/router"
	"github.com/stacklok/toolhive/pkg/vmcp/server/adapter"
)

const (
	// defaultReadHeaderTimeout prevents slowloris attacks by limiting time to read request headers.
	defaultReadHeaderTimeout = 10 * time.Second

	// defaultReadTimeout is the maximum duration for reading the entire request, including body.
	defaultReadTimeout = 30 * time.Second

	// defaultWriteTimeout is the maximum duration before timing out writes of the response.
	defaultWriteTimeout = 30 * time.Second

	// defaultIdleTimeout is the maximum amount of time to wait for the next request when keep-alive's are enabled.
	defaultIdleTimeout = 120 * time.Second

	// defaultMaxHeaderBytes is the maximum size of request headers in bytes (1 MB).
	defaultMaxHeaderBytes = 1 << 20

	// defaultShutdownTimeout is the maximum time to wait for graceful shutdown.
	defaultShutdownTimeout = 10 * time.Second

	// defaultSessionTTL is the default session time-to-live duration.
	// Sessions that are inactive for this duration will be automatically cleaned up.
	defaultSessionTTL = 30 * time.Minute
)

// Config holds the Virtual MCP Server configuration.
type Config struct {
	// Name is the server name exposed in MCP protocol
	Name string

	// Version is the server version
	Version string

	// Host is the bind address (default: "127.0.0.1")
	Host string

	// Port is the bind port (default: 4483)
	Port int

	// EndpointPath is the MCP endpoint path (default: "/mcp")
	EndpointPath string

	// SessionTTL is the session time-to-live duration (default: 30 minutes)
	// Sessions inactive for this duration will be automatically cleaned up
	SessionTTL time.Duration

	// AuthMiddleware is the optional authentication middleware to apply to MCP routes.
	// If nil, no authentication is required.
	// This should be a composed middleware chain (e.g., TokenValidator → IdentityMiddleware).
	AuthMiddleware func(http.Handler) http.Handler

	// AuthInfoHandler is the optional handler for /.well-known/oauth-protected-resource endpoint.
	// Exposes OIDC discovery information about the protected resource.
	AuthInfoHandler http.Handler
}

// Server is the Virtual MCP Server that aggregates multiple backends.
type Server struct {
	config *Config

	// MCP protocol server (mark3labs/mcp-go)
	mcpServer *server.MCPServer

	// HTTP server for Streamable HTTP transport
	httpServer *http.Server

	// Network listener (tracks actual bound port when using port 0)
	listener   net.Listener
	listenerMu sync.RWMutex

	// Router for forwarding requests to backends
	router router.Router

	// Backend client for making requests to backends
	backendClient vmcp.BackendClient

	// Handler factory for creating MCP request handlers
	handlerFactory *adapter.DefaultHandlerFactory

	// Discovery manager for lazy per-user capability discovery
	discoveryMgr discovery.Manager

	// Backends for capability discovery
	backends []vmcp.Backend

	// Session manager for tracking MCP protocol sessions
	// This is ToolHive's session.Manager (pkg/transport/session) - the same component
	// used by streamable proxy for MCP session tracking. It handles:
	//   - Session storage and retrieval
	//   - TTL-based cleanup of inactive sessions
	//   - Session lifecycle management
	// The mark3labs SDK calls our sessionIDAdapter, which delegates to this manager.
	// The SDK does NOT manage sessions itself - it only provides the interface.
	sessionManager *session.Manager

	// Injector for adding capabilities to SDK sessions
	injector *SessionCapabilityInjector

	// Ready channel signals when the server is ready to accept connections.
	// Closed once the listener is created and serving.
	ready     chan struct{}
	readyOnce sync.Once
}

// New creates a new Virtual MCP Server instance.
//
//nolint:gocyclo // Complexity from hook logic is acceptable
func New(
	cfg *Config,
	rt router.Router,
	backendClient vmcp.BackendClient,
	discoveryMgr discovery.Manager,
	backends []vmcp.Backend,
) *Server {
	// Apply defaults
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 4483
	}
	if cfg.EndpointPath == "" {
		cfg.EndpointPath = "/mcp"
	}
	if cfg.Name == "" {
		cfg.Name = "toolhive-vmcp"
	}
	if cfg.Version == "" {
		cfg.Version = "0.1.0"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = defaultSessionTTL
	}

	// Create hooks for SDK integration
	hooks := &server.Hooks{}

	// Create mark3labs MCP server
	mcpServer := server.NewMCPServer(
		cfg.Name,
		cfg.Version,
		server.WithToolCapabilities(false), // We'll register tools dynamically
		server.WithLogging(),
		server.WithHooks(hooks),
	)

	// Create session manager for Streamable HTTP sessions
	sessionManager := session.NewTypedManager(cfg.SessionTTL, session.SessionTypeStreamable)

	// Create handler factory (used by adapter and for future dynamic registration)
	handlerFactory := adapter.NewDefaultHandlerFactory(rt, backendClient)

	// Create Server instance
	srv := &Server{
		config:         cfg,
		mcpServer:      mcpServer,
		router:         rt,
		backendClient:  backendClient,
		handlerFactory: handlerFactory,
		discoveryMgr:   discoveryMgr,
		backends:       backends,
		sessionManager: sessionManager,
		ready:          make(chan struct{}),
	}

	// Create adapter (single source of truth for capability injection)
	capabilityAdapter := adapter.NewCapabilityAdapter(handlerFactory)
	injector := NewSessionCapabilityInjector(mcpServer, capabilityAdapter)
	srv.injector = injector

	// Register post-initialize handler to populate capabilities after SDK creates session
	hooks.AddAfterInitialize(func(ctx context.Context, _ any, _ *mcp.InitializeRequest, _ *mcp.InitializeResult) {
		// Get session from context (already initialized by SDK)
		clientSession := server.ClientSessionFromContext(ctx)
		if clientSession == nil {
			logger.Warnw("no session in context for initialize hook")
			return
		}

		sessionID := clientSession.SessionID()
		logger.Debugw("post-initialize hook called", "session_id", sessionID)

		// Get capabilities from context (discovered by middleware)
		caps, ok := discovery.DiscoveredCapabilitiesFromContext(ctx)
		if !ok || caps == nil {
			logger.Warnw("no discovered capabilities in context for initialize hook",
				"session_id", sessionID)
			return
		}

		// Delegate to injector (single source of truth)
		if err := injector.PopulateCapabilities(sessionID, caps); err != nil {
			logger.Errorw("failed to inject session capabilities",
				"error", err,
				"session_id", sessionID)
			return
		}

		logger.Infow("session capabilities injected via injector",
			"session_id", sessionID)
	})

	return srv
}

// Start starts the Virtual MCP Server and begins serving requests.
func (s *Server) Start(ctx context.Context) error {
	// Create session adapter to expose ToolHive's session.Manager via SDK interface
	// Sessions are ENTIRELY managed by ToolHive's session.Manager (storage, TTL, cleanup).
	// The SDK only calls our Generate/Validate/Terminate methods during MCP protocol flows.
	sessionAdapter := newSessionIDAdapter(s.sessionManager)

	// Create Streamable HTTP server with ToolHive session management
	streamableServer := server.NewStreamableHTTPServer(
		s.mcpServer,
		server.WithEndpointPath(s.config.EndpointPath),
		server.WithSessionIdManager(sessionAdapter),
	)

	// Create HTTP mux with separated authenticated and unauthenticated routes
	mux := http.NewServeMux()

	// Unauthenticated health endpoints
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ping", s.handleHealth)

	// Optional .well-known discovery endpoints (unauthenticated, RFC 9728 compliant)
	// Handles /.well-known/oauth-protected-resource and subpaths (e.g., /mcp)
	if wellKnownHandler := auth.NewWellKnownHandler(s.config.AuthInfoHandler); wellKnownHandler != nil {
		mux.Handle("/.well-known/", wellKnownHandler)
		logger.Info("RFC 9728 OAuth discovery endpoints enabled at /.well-known/")
	}

	// MCP endpoint - apply middleware chain: auth → discovery
	var mcpHandler http.Handler = streamableServer

	// Apply discovery middleware (runs after auth middleware)
	// Discovery middleware performs per-request capability aggregation with user context
	mcpHandler = discovery.Middleware(s.discoveryMgr, s.backends, s)(mcpHandler)
	logger.Info("Discovery middleware enabled for lazy per-user capability discovery")

	// Apply authentication middleware if configured (runs first in chain)
	if s.config.AuthMiddleware != nil {
		mcpHandler = s.config.AuthMiddleware(mcpHandler)
		logger.Info("Authentication middleware enabled for MCP endpoints")
	}

	mux.Handle("/", mcpHandler)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}

	// Create listener (allows port 0 to bind to random available port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.listenerMu.Lock()
	s.listener = listener
	s.listenerMu.Unlock()

	actualAddr := listener.Addr().String()
	logger.Infof("Starting Virtual MCP Server at %s%s", actualAddr, s.config.EndpointPath)
	logger.Infof("Health endpoints available at %s/health and %s/ping", actualAddr, actualAddr)

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Signal that the server is ready (listener created and serving started)
	s.readyOnce.Do(func() {
		close(s.ready)
	})

	// Wait for either context cancellation or server error
	select {
	case <-ctx.Done():
		logger.Info("Context cancelled, shutting down server")
		return s.Stop(context.Background())
	case err := <-errCh:
		return err
	}
}

// Stop gracefully stops the Virtual MCP Server.
func (s *Server) Stop(ctx context.Context) error {
	logger.Info("Stopping Virtual MCP Server")

	var errs []error

	// Stop HTTP server (this internally closes the listener)
	if s.httpServer != nil {
		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(ctx, defaultShutdownTimeout)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown HTTP server: %w", err))
		}
	}

	// Clear listener reference (already closed by httpServer.Shutdown)
	s.listenerMu.Lock()
	s.listener = nil
	s.listenerMu.Unlock()

	// Stop session manager after HTTP server shutdown
	if s.sessionManager != nil {
		if err := s.sessionManager.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop session manager: %w", err))
		}
	}

	if len(errs) > 0 {
		logger.Errorf("Errors during shutdown: %v", errs)
		return errors.Join(errs...)
	}

	logger.Info("Virtual MCP Server stopped")
	return nil
}

// Address returns the server's actual listen address.
// If the server is started with port 0, this returns the actual bound port.
func (s *Server) Address() string {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()

	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// registerTool registers a single tool with the MCP server.
// The tool handler routes the request to the appropriate backend.
//
// NOTE: This function is currently unused due to lazy discovery implementation (issue #2501).
// It will be used when we implement dynamic handler registration based on discovered capabilities.
// Keeping it for now as it contains important handler logic.
//
//nolint:unparam,unused // Error return kept for future extensibility; unused until dynamic registration
func (s *Server) registerTool(tool vmcp.Tool) error {
	// Convert vmcp.Tool to mcp.Tool
	// Note: tool.InputSchema is already a complete JSON Schema (map[string]any)
	// containing type, properties, required, etc. We marshal it to JSON and
	// use RawInputSchema to avoid double-nesting the schema structure.
	schemaJSON, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return fmt.Errorf("failed to marshal input schema for tool %s: %w", tool.Name, err)
	}

	mcpTool := mcp.Tool{
		Name:           tool.Name,
		Description:    tool.Description,
		RawInputSchema: schemaJSON,
	}

	// Create handler that routes to backend
	handler := s.handlerFactory.CreateToolHandler(tool.Name)

	// Register with MCP server
	s.mcpServer.AddTool(mcpTool, handler)

	logger.Debugf("Registered tool: %s", tool.Name)
	return nil
}

// registerResource registers a single resource with the MCP server.
// The resource handler routes the request to the appropriate backend.
//
// NOTE: This function is currently unused due to lazy discovery implementation (issue #2501).
// It will be used when we implement dynamic handler registration based on discovered capabilities.
//
//nolint:unparam,unused // Error return kept for future extensibility; unused until dynamic registration
func (s *Server) registerResource(resource vmcp.Resource) error {
	// Convert vmcp.Resource to mcp.Resource
	mcpResource := mcp.Resource{
		URI:         resource.URI,
		Name:        resource.Name,
		Description: resource.Description,
		MIMEType:    resource.MimeType,
	}

	// Create handler that routes to backend
	handler := s.handlerFactory.CreateResourceHandler(resource.URI)

	// Register with MCP server
	s.mcpServer.AddResource(mcpResource, handler)

	logger.Debugf("Registered resource: %s (MIME: %s)", resource.URI, resource.MimeType)
	return nil
}

// registerPrompt registers a single prompt with the MCP server.
// The prompt handler routes the request to the appropriate backend.
//
// NOTE: This function is currently unused due to lazy discovery implementation (issue #2501).
// It will be used when we implement dynamic handler registration based on discovered capabilities.
//
//nolint:unparam,unused // Error return kept for future extensibility; unused until dynamic registration
func (s *Server) registerPrompt(prompt vmcp.Prompt) error {
	// Convert vmcp.Prompt to mcp.Prompt
	mcpArguments := make([]mcp.PromptArgument, len(prompt.Arguments))
	for i, arg := range prompt.Arguments {
		mcpArguments[i] = mcp.PromptArgument{
			Name:        arg.Name,
			Description: arg.Description,
			Required:    arg.Required,
		}
	}

	mcpPrompt := mcp.Prompt{
		Name:        prompt.Name,
		Description: prompt.Description,
		Arguments:   mcpArguments,
	}

	// Create handler that routes to backend
	handler := s.handlerFactory.CreatePromptHandler(prompt.Name)

	// Register with MCP server
	s.mcpServer.AddPrompt(mcpPrompt, handler)

	logger.Debugf("Registered prompt: %s", prompt.Name)
	return nil
}

// handleHealth handles /health and /ping HTTP requests.
// Returns 200 OK if the server is running and able to respond.
//
// Security Note: This endpoint is unauthenticated and intentionally minimal.
// It only confirms the HTTP server is responding. No version information,
// session counts, or operational metrics are exposed to prevent information
// disclosure in multi-tenant scenarios.
//
// For operational monitoring, implement an authenticated /metrics endpoint
// that requires proper authorization.
func (*Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	response := map[string]string{
		"status": "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	// Always send 200 OK - even if JSON encoding fails below, the server is responding
	w.WriteHeader(http.StatusOK)

	// Encode response. If this fails (extremely unlikely for simple map[string]string),
	// the 200 OK status has already been sent above.
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Failed to encode health response: %v", err)
	}
}

// SessionManager returns the session manager instance.
// This is useful for testing and monitoring.
func (s *Server) SessionManager() *session.Manager {
	return s.sessionManager
}

// PopulateCapabilities implements discovery.CapabilityPopulator interface.
// This allows the discovery middleware to trigger capability injection for subsequent requests.
// Delegates to injector (single source of truth for capability injection logic).
func (s *Server) PopulateCapabilities(sessionID string, caps *aggregator.AggregatedCapabilities) error {
	return s.injector.PopulateCapabilities(sessionID, caps)
}

// Ready returns a channel that is closed when the server is ready to accept connections.
// This is useful for testing and synchronization.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}
