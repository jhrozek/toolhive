// Package discovery provides lazy per-user capability discovery for vMCP servers.
package discovery

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/stacklok/toolhive/pkg/logger"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/aggregator"
)

const (
	// discoveryTimeout is the maximum time for capability discovery.
	discoveryTimeout = 15 * time.Second
)

// CapabilityPopulator defines the interface for populating session capabilities.
// This allows the middleware to trigger capability population without direct
// coupling to the server package (avoiding circular dependencies).
type CapabilityPopulator interface {
	// PopulateCapabilities initializes and populates session capabilities
	// for the given session ID using the discovered capabilities.
	PopulateCapabilities(sessionID string, caps *aggregator.AggregatedCapabilities) error
}

// Middleware creates an HTTP middleware that performs per-request capability discovery.
// This middleware MUST be placed after authentication middleware in the handler chain.
//
// Discovery flow:
//  1. Creates a timeout context for discovery operations (5 seconds)
//  2. Performs capability aggregation from backends
//  3. Injects discovered capabilities into request context
//  4. For initialize requests (no session ID): defers to hook, continues
//  5. For subsequent requests (has session ID): populates session capabilities
//
// Error handling returns HTTP 504 for timeout/cancellation, HTTP 503 for other errors.
// Capability population errors are logged but don't fail the request.
func Middleware(manager Manager, backends []vmcp.Backend, populator CapabilityPopulator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
			defer cancel()

			logger.Debugw("starting capability discovery",
				"method", r.Method,
				"path", r.URL.Path,
				"backend_count", len(backends))

			capabilities, err := manager.Discover(discoveryCtx, backends)
			if err != nil {
				logger.Errorw("capability discovery failed",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path)

				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					http.Error(w, http.StatusText(http.StatusGatewayTimeout), http.StatusGatewayTimeout)
					return
				}

				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				return
			}

			logger.Debugw("capability discovery completed",
				"method", r.Method,
				"path", r.URL.Path,
				"tool_count", len(capabilities.Tools),
				"resource_count", len(capabilities.Resources),
				"prompt_count", len(capabilities.Prompts))

			// Store capabilities in context (needed by both hook and subsequent requests)
			ctx = WithDiscoveredCapabilities(ctx, capabilities)

			// Two-phase population logic:
			// Phase 1 (initialize request): Session ID is empty, defer to hook
			// Phase 2 (subsequent requests): Session ID present, populate now
			sessionID := r.Header.Get("Mcp-Session-Id")
			if sessionID != "" {
				// Subsequent request - populate session capabilities
				logger.Debugw("populating session capabilities for subsequent request",
					"session_id", sessionID)

				if err := populator.PopulateCapabilities(sessionID, capabilities); err != nil {
					// Log but don't fail the request - session may already be populated
					logger.Warnw("failed to populate session capabilities in middleware",
						"error", err,
						"session_id", sessionID)
				}
			} else {
				// Initialize request - let the hook handle population
				logger.Debugw("deferring capability population to initialize hook")
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
