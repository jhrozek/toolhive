// Package discovery provides lazy per-user capability discovery for vMCP servers.
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
	discoveryTimeout = 5 * time.Second
)

// Middleware creates an HTTP middleware that performs per-request capability discovery.
// This middleware MUST be placed after authentication middleware in the handler chain.
//
// Discovery flow:
//  1. Creates a timeout context for discovery operations (5 seconds)
//  2. Performs capability aggregation from backends
//  3. Injects discovered capabilities into request context
//  4. Passes control to next handler with enriched context
//
// Error handling returns HTTP 504 for timeout/cancellation, HTTP 503 for other errors.
func Middleware(manager Manager, backends []vmcp.Backend) func(http.Handler) http.Handler {
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

			ctx = WithDiscoveredCapabilities(ctx, capabilities)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
