// Package discovery provides lazy per-user capability discovery for vMCP servers.
//
// Capabilities are discovered at session initialization time and remain fixed for
// the session lifetime. This ensures deterministic behavior and prevents notification
// spam from redundant capability updates when backends haven't changed.
//
// Future enhancement: Background capability refresh with diff detection to handle
// dynamic backend changes during long-lived sessions.
package discovery

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/stacklok/toolhive/pkg/logger"
	"github.com/stacklok/toolhive/pkg/vmcp"
)

const (
	// discoveryTimeout is the maximum time for capability discovery.
	discoveryTimeout = 15 * time.Second
)

// Middleware creates an HTTP middleware that performs capability discovery only on session initialization.
// This middleware MUST be placed after authentication middleware in the handler chain.
//
// Discovery flow:
//  1. For initialize requests (no session ID):
//     - Creates a timeout context for discovery operations (15 seconds)
//     - Performs capability aggregation from backends
//     - Injects discovered capabilities into request context
//     - Defers capability population to AfterInitialize hook
//  2. For subsequent requests (has session ID):
//     - Skips discovery entirely to prevent notification spam
//     - Uses existing session capabilities
//
// Error handling returns HTTP 504 for timeout/cancellation, HTTP 503 for other errors.
func Middleware(manager Manager, backends []vmcp.Backend) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			sessionID := r.Header.Get("Mcp-Session-Id")

			// Only discover capabilities for initialize requests (no session ID yet).
			// Subsequent requests use capabilities already injected during initialize.
			// This prevents notification spam from redundant delete/add cycles when
			// capabilities haven't actually changed.
			//
			// Rationale:
			// - Session capabilities are immutable after creation
			// - Backend changes are rare (minutes to hours between changes)
			// - Current delete-all-then-add-all causes 2 notifications per request
			// - Violates MCP spec: tools/list_changed should only fire on actual changes
			//
			// TODO: Future enhancement for dynamic backend updates:
			// - Implement per-session capability cache with TTL
			// - Add background refresh worker with diff detection
			// - Only send tools/list_changed notifications on actual changes
			// - Consider: explicit session refresh API endpoint
			if sessionID == "" {
				discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
				defer cancel()

				logger.Debugw("starting capability discovery for initialize request",
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

				// Store capabilities in context for AfterInitialize hook
				ctx = WithDiscoveredCapabilities(ctx, capabilities)
			} else {
				// Subsequent request - skip discovery, use existing session capabilities
				logger.Debugw("skipping capability discovery for subsequent request",
					"session_id", sessionID,
					"method", r.Method,
					"path", r.URL.Path)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
