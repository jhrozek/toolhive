package server

import (
	"fmt"

	"github.com/mark3labs/mcp-go/server"

	"github.com/stacklok/toolhive/pkg/logger"
	"github.com/stacklok/toolhive/pkg/vmcp/aggregator"
	"github.com/stacklok/toolhive/pkg/vmcp/server/adapter"
)

// SessionCapabilityInjector injects capabilities into SDK sessions from aggregated capabilities.
//
// This is the single source of truth for capability injection logic.
// It coordinates:
//  1. Adapter: Converts aggregator types to SDK types
//  2. SDK API: Registers capabilities using AddSessionTools/AddSessionResources
//
// Used in two places:
//   - AfterInitialize hook: Inject capabilities after SDK creates session
//   - PopulateCapabilities method: Re-inject capabilities for subsequent requests (via discovery middleware)
type SessionCapabilityInjector struct {
	mcpServer *server.MCPServer
	adapter   *adapter.CapabilityAdapter
}

// NewSessionCapabilityInjector creates a new session capability injector.
func NewSessionCapabilityInjector(
	mcpServer *server.MCPServer,
	capabilityAdapter *adapter.CapabilityAdapter,
) *SessionCapabilityInjector {
	return &SessionCapabilityInjector{
		mcpServer: mcpServer,
		adapter:   capabilityAdapter,
	}
}

// PopulateCapabilities injects capabilities into SDK session from aggregated capabilities.
//
// This method:
//  1. Converts aggregator types to SDK types using adapter
//  2. Calls SDK's AddSessionTools/AddSessionResources to register capabilities
//  3. Logs appropriately
//
// Note: SDK v0.43.0 does not support per-session prompts yet.
func (i *SessionCapabilityInjector) PopulateCapabilities(
	sessionID string,
	caps *aggregator.AggregatedCapabilities,
) error {
	// Convert and inject tools
	if len(caps.Tools) > 0 {
		sdkTools, err := i.adapter.ToSDKTools(caps.Tools)
		if err != nil {
			return fmt.Errorf("failed to convert tools to SDK format: %w", err)
		}

		if err := i.mcpServer.AddSessionTools(sessionID, sdkTools...); err != nil {
			return fmt.Errorf("failed to add session tools: %w", err)
		}
		logger.Debugw("injected session tools", "session_id", sessionID, "count", len(sdkTools))
	}

	// Convert and inject resources
	if len(caps.Resources) > 0 {
		sdkResources := i.adapter.ToSDKResources(caps.Resources)

		if err := i.mcpServer.AddSessionResources(sessionID, sdkResources...); err != nil {
			return fmt.Errorf("failed to add session resources: %w", err)
		}
		logger.Debugw("injected session resources", "session_id", sessionID, "count", len(sdkResources))
	}

	// Note: SDK v0.43.0 does not support per-session prompts yet.
	// Prompts would need to be added globally via mcpServer.AddPrompt()
	if len(caps.Prompts) > 0 {
		logger.Debugw("skipping prompts - SDK does not support per-session prompts yet",
			"session_id", sessionID,
			"prompt_count", len(caps.Prompts))
	}

	logger.Infow("session capabilities injected",
		"session_id", sessionID,
		"tools", len(caps.Tools),
		"resources", len(caps.Resources))

	return nil
}
