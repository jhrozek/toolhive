// Package session provides vMCP-specific session types that extend transport sessions with domain logic.
package session

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/stacklok/toolhive/pkg/logger"
	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
)

// VMCPSession extends StreamableSession with domain-specific routing data.
// This keeps routing table state in the application layer (pkg/vmcp/server)
// rather than polluting the transport layer (pkg/transport/session) with domain concerns.
//
// Design Rationale:
//   - Embeds StreamableSession to inherit Session interface and streamable HTTP behavior
//   - Adds routing table for per-session capability routing
//   - Maintains lifecycle synchronization with underlying transport session
//   - Provides type-safe access to routing table (vs. interface{} casting)
//
// Lifecycle:
//  1. Created by VMCPSessionFactory during sessionIDAdapter.Generate()
//  2. Routing table populated in AfterInitialize hook
//  3. Retrieved by middleware on subsequent requests via type assertion
//  4. Cleaned up automatically by session.Manager TTL worker
type VMCPSession struct {
	*transportsession.StreamableSession
	routingTable *vmcp.RoutingTable
	mu           sync.RWMutex
}

// NewVMCPSession creates a VMCPSession with initialized StreamableSession.
// The routing table is initially nil and will be populated during AfterInitialize hook.
func NewVMCPSession(id string) *VMCPSession {
	streamableSession := transportsession.NewStreamableSession(id)

	// Type assertion safe because NewStreamableSession always returns *StreamableSession
	ss, ok := streamableSession.(*transportsession.StreamableSession)
	if !ok {
		logger.Errorf("Failed to create StreamableSession for VMCPSession %s", id)
		// Fallback: return VMCPSession with basic ProxySession
		return &VMCPSession{
			StreamableSession: &transportsession.StreamableSession{
				ProxySession: transportsession.NewTypedProxySession(id, transportsession.SessionTypeStreamable),
			},
			routingTable: nil,
		}
	}

	return &VMCPSession{
		StreamableSession: ss,
		routingTable:      nil,
	}
}

// GetRoutingTable retrieves the routing table for this session.
// Returns nil if capabilities have not been initialized yet.
func (s *VMCPSession) GetRoutingTable() *vmcp.RoutingTable {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routingTable
}

// SetRoutingTable sets the routing table for this session.
// Called during AfterInitialize hook after capability discovery.
func (s *VMCPSession) SetRoutingTable(rt *vmcp.RoutingTable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routingTable = rt
}

// GetData overrides StreamableSession.GetData() to return routing table for serialization.
// This enables distributed storage backends (Redis/Valkey) to persist routing tables.
func (s *VMCPSession) GetData() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routingTable
}

// SetData overrides StreamableSession.SetData() to handle routing table deserialization.
// Supports both direct *RoutingTable objects and json.RawMessage from storage backends.
func (s *VMCPSession) SetData(data interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch v := data.(type) {
	case *vmcp.RoutingTable:
		s.routingTable = v
	case json.RawMessage:
		var rt vmcp.RoutingTable
		if err := json.Unmarshal(v, &rt); err != nil {
			logger.Errorw("failed to deserialize routing table",
				"session_id", s.ID(),
				"error", err)
			s.routingTable = nil
			return
		}
		s.routingTable = &rt
	case nil:
		s.routingTable = nil
	default:
		logger.Warnw("SetData called with unexpected type",
			"session_id", s.ID(),
			"type", fmt.Sprintf("%T", data))
		s.routingTable = nil
	}
}

// Type identifies this as a streamable vMCP session.
func (*VMCPSession) Type() transportsession.SessionType {
	return transportsession.SessionTypeStreamable
}

// VMCPSessionFactory creates a factory function for the session manager.
func VMCPSessionFactory() transportsession.Factory {
	return func(id string) transportsession.Session {
		return NewVMCPSession(id)
	}
}
