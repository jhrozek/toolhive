package router

import (
	"context"
	"fmt"

	"github.com/stacklok/toolhive/pkg/logger"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/discovery"
)

// defaultRouter is a stateless router implementation that retrieves routing
// information from the request context. With lazy discovery, capabilities are
// discovered per-request and stored in context by the discovery middleware.
//
// This router is thread-safe by design since it maintains no mutable state.
type defaultRouter struct {
	// No fields - routing table comes from request context
}

// NewDefaultRouter creates a new default router instance.
func NewDefaultRouter() Router {
	return &defaultRouter{}
}

// RouteTool resolves a tool name to its backend target.
// With lazy discovery, this method gets capabilities from the request context
// instead of using a cached routing table.
func (*defaultRouter) RouteTool(ctx context.Context, toolName string) (*vmcp.BackendTarget, error) {
	// Get capabilities from context (set by discovery middleware)
	capabilities, ok := discovery.DiscoveredCapabilitiesFromContext(ctx)
	if !ok || capabilities == nil {
		return nil, fmt.Errorf("capabilities not found in context - discovery middleware may not have run")
	}

	if capabilities.RoutingTable == nil {
		return nil, fmt.Errorf("routing table not initialized in discovered capabilities")
	}

	if capabilities.RoutingTable.Tools == nil {
		return nil, fmt.Errorf("routing table tools map not initialized")
	}

	target, exists := capabilities.RoutingTable.Tools[toolName]
	if !exists {
		logger.Debugf("Tool not found in routing table: %s", toolName)
		return nil, fmt.Errorf("%w: %s", ErrToolNotFound, toolName)
	}

	logger.Debugf("Routed tool %s to backend %s", toolName, target.WorkloadID)
	return target, nil
}

// RouteResource resolves a resource URI to its backend target.
// With lazy discovery, this method gets capabilities from the request context
// instead of using a cached routing table.
func (*defaultRouter) RouteResource(ctx context.Context, uri string) (*vmcp.BackendTarget, error) {
	// Get capabilities from context (set by discovery middleware)
	capabilities, ok := discovery.DiscoveredCapabilitiesFromContext(ctx)
	if !ok || capabilities == nil {
		return nil, fmt.Errorf("capabilities not found in context - discovery middleware may not have run")
	}

	if capabilities.RoutingTable == nil {
		return nil, fmt.Errorf("routing table not initialized in discovered capabilities")
	}

	if capabilities.RoutingTable.Resources == nil {
		return nil, fmt.Errorf("routing table resources map not initialized")
	}

	target, exists := capabilities.RoutingTable.Resources[uri]
	if !exists {
		logger.Debugf("Resource not found in routing table: %s", uri)
		return nil, fmt.Errorf("%w: %s", ErrResourceNotFound, uri)
	}

	logger.Debugf("Routed resource %s to backend %s", uri, target.WorkloadID)
	return target, nil
}

// RoutePrompt resolves a prompt name to its backend target.
// With lazy discovery, this method gets capabilities from the request context
// instead of using a cached routing table.
func (*defaultRouter) RoutePrompt(ctx context.Context, name string) (*vmcp.BackendTarget, error) {
	// Get capabilities from context (set by discovery middleware)
	capabilities, ok := discovery.DiscoveredCapabilitiesFromContext(ctx)
	if !ok || capabilities == nil {
		return nil, fmt.Errorf("capabilities not found in context - discovery middleware may not have run")
	}

	if capabilities.RoutingTable == nil {
		return nil, fmt.Errorf("routing table not initialized in discovered capabilities")
	}

	if capabilities.RoutingTable.Prompts == nil {
		return nil, fmt.Errorf("routing table prompts map not initialized")
	}

	target, exists := capabilities.RoutingTable.Prompts[name]
	if !exists {
		logger.Debugf("Prompt not found in routing table: %s", name)
		return nil, fmt.Errorf("%w: %s", ErrPromptNotFound, name)
	}

	logger.Debugf("Routed prompt %s to backend %s", name, target.WorkloadID)
	return target, nil
}
