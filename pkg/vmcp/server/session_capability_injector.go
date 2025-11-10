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
// This is the single source of truth for capability injection logic during session creation.
// It coordinates:
//  1. Adapter: Converts aggregator types to SDK types
//  2. SDK API: Registers capabilities using AddSessionTools/AddSessionResources
//
// Lifecycle:
//   - Called ONCE per session during AfterInitialize hook (after SDK creates session)
//   - Session is brand new (empty) at injection time, so no previous state to manage
//   - Capabilities remain fixed for session lifetime (no re-injection on subsequent requests)
//
// Why no tracking is needed:
//   - Discovery middleware only runs on initialize (no session ID), not on subsequent requests
//   - InjectCapabilities is only called once when session is created (empty state)
//   - No need to delete previous capabilities (there are none - session is new)
//   - Session capabilities are immutable after creation
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

// InjectCapabilities injects capabilities into a newly created SDK session.
//
// This method is called ONCE per session during the AfterInitialize hook, when the
// session has just been created by the SDK and is empty. It:
//  1. Converts aggregator types to SDK types using adapter
//  2. Adds discovered capabilities via SDK APIs (AddSessionTools, AddSessionResources)
//
// Important constraints:
//   - Called only during session creation (session state is empty)
//   - No previous capabilities exist, so no deletion needed
//   - Capabilities are immutable for the session lifetime
//   - Discovery middleware does not re-run for subsequent requests
//
// Note: SDK v0.43.0 does not support per-session prompts yet.
func (i *SessionCapabilityInjector) InjectCapabilities(
	sessionID string,
	caps *aggregator.AggregatedCapabilities,
) error {
	// Convert and add tools
	if len(caps.Tools) > 0 {
		sdkTools, err := i.adapter.ToSDKTools(caps.Tools)
		if err != nil {
			return fmt.Errorf("failed to convert tools to SDK format: %w", err)
		}

		if err := i.mcpServer.AddSessionTools(sessionID, sdkTools...); err != nil {
			return fmt.Errorf("failed to add session tools: %w", err)
		}
		logger.Debugw("added session tools", "session_id", sessionID, "count", len(sdkTools))
	}

	// Convert and add resources
	if len(caps.Resources) > 0 {
		sdkResources := i.adapter.ToSDKResources(caps.Resources)

		if err := i.mcpServer.AddSessionResources(sessionID, sdkResources...); err != nil {
			return fmt.Errorf("failed to add session resources: %w", err)
		}
		logger.Debugw("added session resources", "session_id", sessionID, "count", len(sdkResources))
	}

	// Note: SDK v0.43.0 does not support per-session prompts yet.
	// Prompts would need to be added globally via mcpServer.AddPrompt()
	if len(caps.Prompts) > 0 {
		logger.Debugw("skipping prompts - SDK does not support per-session prompts yet",
			"session_id", sessionID,
			"prompt_count", len(caps.Prompts))
	}

	logger.Infow("session capabilities injected during initialization",
		"session_id", sessionID,
		"tools", len(caps.Tools),
		"resources", len(caps.Resources))

	return nil
}
