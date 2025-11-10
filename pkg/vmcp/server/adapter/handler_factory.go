// Package adapter provides Anti-Corruption Layer between aggregator and SDK.
//
// This package isolates the server from knowing about aggregator's internal types,
// maintaining proper bounded context boundaries.
//
// The HandlerFactory interface and its default implementation create MCP request
// handlers that route to backend workloads, bridging the gap between the MCP SDK
// and the vMCP domain logic.
package adapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/stacklok/toolhive/pkg/logger"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/discovery"
	"github.com/stacklok/toolhive/pkg/vmcp/router"
)

// HandlerFactory creates handlers that route MCP requests to backends.
// This abstracts handler creation logic, allowing the adapter to create handlers
// without knowing about implementation details.
//
// The default implementation (DefaultHandlerFactory) routes requests through
// the router to backend workloads.
type HandlerFactory interface {
	// CreateToolHandler creates a handler that routes tool calls to backends.
	// The handler is responsible for:
	//   - Looking up the target backend via routing
	//   - Converting MCP request format to backend format
	//   - Forwarding the request and handling errors
	CreateToolHandler(toolName string) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)

	// CreateResourceHandler creates a handler that routes resource reads to backends.
	// The handler is responsible for:
	//   - Looking up the target backend via routing
	//   - Reading the resource data from the backend
	//   - Converting backend data to MCP ResourceContents format
	CreateResourceHandler(uri string) func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error)

	// CreatePromptHandler creates a handler that routes prompt requests to backends.
	// The handler is responsible for:
	//   - Looking up the target backend via routing
	//   - Forwarding the prompt request to the backend
	//   - Converting backend response to MCP GetPromptResult format
	CreatePromptHandler(promptName string) func(context.Context, mcp.GetPromptRequest) (*mcp.GetPromptResult, error)
}

// DefaultHandlerFactory creates MCP request handlers that route to backend workloads.
// This is the default implementation of HandlerFactory.
//
// It has minimal dependencies (only router + backend client), making it:
//   - Highly testable (mock router + client, no need for full Server)
//   - Loosely coupled (no dependency on Server internals)
//   - Single responsibility (only creates handlers, doesn't manage server lifecycle)
type DefaultHandlerFactory struct {
	router        router.Router
	backendClient vmcp.BackendClient
}

// NewDefaultHandlerFactory creates a new default handler factory.
func NewDefaultHandlerFactory(rt router.Router, backendClient vmcp.BackendClient) *DefaultHandlerFactory {
	return &DefaultHandlerFactory{
		router:        rt,
		backendClient: backendClient,
	}
}

// CreateToolHandler creates a tool handler that routes to the appropriate backend.
// Called by CapabilityAdapter to create handlers for discovered tools.
func (f *DefaultHandlerFactory) CreateToolHandler(
	toolName string,
) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Debugf("Handling tool call: %s", toolName)

		// Route to backend
		target, err := f.router.RouteTool(ctx, toolName)
		if err != nil {
			// Wrap routing errors with domain error
			if errors.Is(err, router.ErrToolNotFound) {
				wrappedErr := fmt.Errorf("%w: tool %s", vmcp.ErrNotFound, toolName)
				logger.Warnf("Routing failed: %v", wrappedErr)
				return mcp.NewToolResultError(wrappedErr.Error()), nil
			}
			logger.Warnf("Failed to route tool %s: %v", toolName, err)
			return mcp.NewToolResultError(fmt.Sprintf("Routing error: %v", err)), nil
		}

		// Convert arguments to map[string]any
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			wrappedErr := fmt.Errorf("%w: arguments must be object, got %T", vmcp.ErrInvalidInput, request.Params.Arguments)
			logger.Warnf("Invalid arguments for tool %s: %v", toolName, wrappedErr)
			return mcp.NewToolResultError(wrappedErr.Error()), nil
		}

		// Get the name to use when calling the backend (handles conflict resolution renaming)
		backendToolName := target.GetBackendCapabilityName(toolName)
		if backendToolName != toolName {
			logger.Debugf("Translating tool name %s -> %s for backend %s",
				toolName, backendToolName, target.WorkloadID)
		}

		// Forward request to backend
		result, err := f.backendClient.CallTool(ctx, target, backendToolName, args)
		if err != nil {
			// Distinguish between domain errors (tool execution failed) and operational errors (backend unavailable)
			if errors.Is(err, vmcp.ErrToolExecutionFailed) {
				// Tool ran but returned error - forward transparently to client
				logger.Debugf("Tool execution failed for %s: %v", toolName, err)
				return mcp.NewToolResultError(err.Error()), nil
			}
			if errors.Is(err, vmcp.ErrBackendUnavailable) {
				// Operational error - backend unreachable
				logger.Warnf("Backend unavailable for tool %s: %v", toolName, err)
				return mcp.NewToolResultError(fmt.Sprintf("Backend unavailable: %v", err)), nil
			}
			// Unknown error type
			logger.Warnf("Backend tool call failed for %s: %v", toolName, err)
			return mcp.NewToolResultError(fmt.Sprintf("Tool call failed: %v", err)), nil
		}

		// Convert result to MCP format
		return mcp.NewToolResultStructuredOnly(result), nil
	}
}

// CreateResourceHandler creates a resource handler that routes to the appropriate backend.
// Called by CapabilityAdapter to create handlers for discovered resources.
func (f *DefaultHandlerFactory) CreateResourceHandler(uri string) func(
	context.Context, mcp.ReadResourceRequest,
) ([]mcp.ResourceContents, error) {
	return func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		logger.Debugf("Handling resource read: %s", uri)

		// Get discovered capabilities from context
		caps, ok := discovery.DiscoveredCapabilitiesFromContext(ctx)
		if !ok {
			logger.Warn("Capabilities not discovered in context")
			return nil, fmt.Errorf("capabilities not discovered")
		}

		// Route to backend
		target, err := f.router.RouteResource(ctx, uri)
		if err != nil {
			// Wrap routing errors with domain error
			if errors.Is(err, router.ErrResourceNotFound) {
				wrappedErr := fmt.Errorf("%w: resource %s", vmcp.ErrNotFound, uri)
				logger.Warnf("Routing failed: %v", wrappedErr)
				return nil, wrappedErr
			}
			logger.Warnf("Failed to route resource %s: %v", uri, err)
			return nil, fmt.Errorf("routing error: %w", err)
		}

		// Get the URI to use when calling the backend (handles conflict resolution renaming)
		backendURI := target.GetBackendCapabilityName(uri)

		// Forward request to backend
		data, err := f.backendClient.ReadResource(ctx, target, backendURI)
		if err != nil {
			// Check if backend is unavailable (operational error)
			if errors.Is(err, vmcp.ErrBackendUnavailable) {
				logger.Warnf("Backend unavailable for resource %s: %v", uri, err)
				return nil, fmt.Errorf("backend unavailable: %w", err)
			}
			// Other errors
			logger.Warnf("Backend resource read failed for %s: %v", uri, err)
			return nil, fmt.Errorf("resource read failed: %w", err)
		}

		// Get resource MIME type from discovered capabilities
		mimeType := "application/octet-stream" // Default for unknown resources
		for _, res := range caps.Resources {
			if res.URI == uri && res.MimeType != "" {
				mimeType = res.MimeType
				break
			}
		}

		// Convert to MCP ResourceContents
		contents := []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      uri,
				MIMEType: mimeType,
				Text:     string(data),
			},
		}

		return contents, nil
	}
}

// CreatePromptHandler creates a prompt handler that routes to the appropriate backend.
//
// NOTE: This function is currently unused due to lazy discovery implementation (issue #2501).
//
//nolint:unused // Unused until dynamic handler registration
func (f *DefaultHandlerFactory) CreatePromptHandler(promptName string) func(
	context.Context, mcp.GetPromptRequest,
) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		logger.Debugf("Handling prompt request: %s", promptName)

		// Route to backend
		target, err := f.router.RoutePrompt(ctx, promptName)
		if err != nil {
			// Wrap routing errors with domain error
			if errors.Is(err, router.ErrPromptNotFound) {
				wrappedErr := fmt.Errorf("%w: prompt %s", vmcp.ErrNotFound, promptName)
				logger.Warnf("Routing failed: %v", wrappedErr)
				return nil, wrappedErr
			}
			logger.Warnf("Failed to route prompt %s: %v", promptName, err)
			return nil, fmt.Errorf("routing error: %w", err)
		}

		// Convert arguments to map[string]any
		args := make(map[string]any)
		for k, v := range request.Params.Arguments {
			args[k] = v
		}

		// Get the name to use when calling the backend (handles conflict resolution renaming)
		backendPromptName := target.GetBackendCapabilityName(promptName)

		// Forward request to backend
		promptText, err := f.backendClient.GetPrompt(ctx, target, backendPromptName, args)
		if err != nil {
			// Check if backend is unavailable (operational error)
			if errors.Is(err, vmcp.ErrBackendUnavailable) {
				logger.Warnf("Backend unavailable for prompt %s: %v", promptName, err)
				return nil, fmt.Errorf("backend unavailable: %w", err)
			}
			// Other errors
			logger.Warnf("Backend prompt request failed for %s: %v", promptName, err)
			return nil, fmt.Errorf("prompt request failed: %w", err)
		}

		// Convert to MCP GetPromptResult
		result := &mcp.GetPromptResult{
			Description: fmt.Sprintf("Prompt: %s", promptName),
			Messages: []mcp.PromptMessage{
				{
					Role:    "assistant",
					Content: mcp.NewTextContent(promptText),
				},
			},
		}

		return result, nil
	}
}
