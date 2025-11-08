// Package discovery provides lazy per-user capability discovery for vMCP servers.
//
// This package implements per-request capability discovery with user-specific
// authentication context, enabling truly multi-tenant operation where different
// users may see different capabilities based on their permissions.
package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/aggregator"
)

//go:generate mockgen -destination=mocks/mock_manager.go -package=mocks -source=manager.go Manager

var (
	// ErrAggregatorNil is returned when aggregator is nil.
	ErrAggregatorNil = errors.New("aggregator cannot be nil")
	// ErrDiscoveryFailed is returned when capability discovery fails.
	ErrDiscoveryFailed = errors.New("capability discovery failed")
)

// Manager performs capability discovery with user context.
type Manager interface {
	// Discover performs capability aggregation for the given backends with user context.
	Discover(ctx context.Context, backends []vmcp.Backend) (*aggregator.AggregatedCapabilities, error)
}

// DefaultManager is the default implementation of Manager.
type DefaultManager struct {
	aggregator aggregator.Aggregator
}

// NewManager creates a new discovery manager with the given aggregator.
func NewManager(agg aggregator.Aggregator) (Manager, error) {
	if agg == nil {
		return nil, ErrAggregatorNil
	}
	return &DefaultManager{
		aggregator: agg,
	}, nil
}

// Discover performs capability aggregation by delegating to the aggregator.
func (m *DefaultManager) Discover(ctx context.Context, backends []vmcp.Backend) (*aggregator.AggregatedCapabilities, error) {
	caps, err := m.aggregator.AggregateCapabilities(ctx, backends)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}

	return caps, nil
}
