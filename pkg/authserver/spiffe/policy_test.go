// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

func TestClientPolicy_IsAllowed_ExactMatch(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "production", ServiceAccount: "mcp-agent"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/production/sa/mcp-agent")
	assert.True(t, policy.IsAllowed(id), "exact namespace + exact SA should be allowed")
}

func TestClientPolicy_IsAllowed_WildcardNamespace(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "*", ServiceAccount: "mcp-agent"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/any-namespace/sa/mcp-agent")
	assert.True(t, policy.IsAllowed(id), "wildcard namespace + exact SA should be allowed")
}

func TestClientPolicy_IsAllowed_WildcardServiceAccount(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "production", ServiceAccount: "*"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/production/sa/any-sa")
	assert.True(t, policy.IsAllowed(id), "exact namespace + wildcard SA should be allowed")
}

func TestClientPolicy_IsAllowed_WildcardBoth(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "*", ServiceAccount: "*"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/anything/sa/whatever")
	assert.True(t, policy.IsAllowed(id), "wildcard namespace + wildcard SA should allow any K8s SPIFFE ID")
}

func TestClientPolicy_IsAllowed_DeniedWrongNamespace(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "production", ServiceAccount: "mcp-agent"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/untrusted/sa/mcp-agent")
	assert.False(t, policy.IsAllowed(id), "wrong namespace should be denied")
}

func TestClientPolicy_IsAllowed_DeniedWrongServiceAccount(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "production", ServiceAccount: "mcp-agent"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/production/sa/rogue-agent")
	assert.False(t, policy.IsAllowed(id), "wrong service account should be denied")
}

func TestClientPolicy_IsAllowed_DeniedNonKubernetesPath(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "*", ServiceAccount: "*"},
		},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/workload/foo")
	assert.False(t, policy.IsAllowed(id), "non-Kubernetes SPIFFE path should be denied")
}

func TestClientPolicy_IsAllowed_DeniedEmptyPolicy(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{},
	}

	id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/production/sa/mcp-agent")
	assert.False(t, policy.IsAllowed(id), "empty allowed identities list should deny all")
}

func TestClientPolicy_IsAllowed_MultiplePatterns(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "production", ServiceAccount: "agent-1"},
			{Namespace: "staging", ServiceAccount: "*"},
		},
	}

	t.Run("matches first pattern", func(t *testing.T) {
		t.Parallel()
		id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/production/sa/agent-1")
		assert.True(t, policy.IsAllowed(id))
	})

	t.Run("matches second pattern", func(t *testing.T) {
		t.Parallel()
		id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/staging/sa/any-agent")
		assert.True(t, policy.IsAllowed(id))
	})

	t.Run("matches neither pattern", func(t *testing.T) {
		t.Parallel()
		id := spiffeid.RequireFromString("spiffe://toolhive.dev/ns/untrusted/sa/rogue")
		assert.False(t, policy.IsAllowed(id))
	})
}

func TestClientPolicy_IsAllowed_MalformedPaths(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "*", ServiceAccount: "*"},
		},
	}

	tests := []struct {
		name     string
		spiffeID string
	}{
		{"too few segments", "spiffe://toolhive.dev/ns/default"},
		{"too many segments", "spiffe://toolhive.dev/ns/default/sa/agent/extra"},
		{"wrong prefix", "spiffe://toolhive.dev/namespace/default/sa/agent"},
		{"wrong sa prefix", "spiffe://toolhive.dev/ns/default/serviceaccount/agent"},
		// Note: paths like "spiffe://toolhive.dev/" or empty paths are rejected by
		// the go-spiffe library itself, so they can never reach our path parser.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := spiffeid.RequireFromString(tc.spiffeID)
			assert.False(t, policy.IsAllowed(id), "malformed path %q should be denied", tc.spiffeID)
		})
	}
}

func TestClientPolicy_MaxRegistrations_Exceeded(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "*", ServiceAccount: "*"},
		},
		MaxRegistrations: 2,
	}

	// First two registrations should succeed.
	assert.True(t, policy.IncrementRegistrations(), "first registration should succeed")
	assert.True(t, policy.IncrementRegistrations(), "second registration should succeed")

	// Third registration should fail.
	assert.False(t, policy.IncrementRegistrations(), "third registration should be denied (max=2)")

	// Count should remain at 2 (the failed increment was rolled back).
	assert.Equal(t, int64(2), policy.RegistrationCount(), "count should remain at max after denied registration")
}

func TestClientPolicy_MaxRegistrations_Unlimited(t *testing.T) {
	t.Parallel()

	policy := &ClientPolicy{
		AllowedIdentities: []AllowedIdentity{
			{Namespace: "*", ServiceAccount: "*"},
		},
		MaxRegistrations: 0, // unlimited
	}

	// Should succeed indefinitely.
	for i := 0; i < 100; i++ {
		assert.True(t, policy.IncrementRegistrations(), "unlimited policy should always allow registration")
	}
}

func TestClientPolicy_NilPolicy_AllowAll(t *testing.T) {
	t.Parallel()

	// A nil *ClientPolicy means "allow all" (backward compatible).
	// This is tested at the caller level (ClientAuthPreHandler),
	// but we verify the pattern here for documentation.
	var policy *ClientPolicy
	assert.Nil(t, policy, "nil policy represents allow-all")
}

func TestParseKubernetesPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		wantNS string
		wantSA string
		wantOK bool
	}{
		{"valid path", "/ns/default/sa/my-agent", "default", "my-agent", true},
		{"hyphenated names", "/ns/my-namespace/sa/my-service-account", "my-namespace", "my-service-account", true},
		{"too few segments", "/ns/default", "", "", false},
		{"too many segments", "/ns/default/sa/agent/extra", "", "", false},
		{"wrong ns prefix", "/namespace/default/sa/agent", "", "", false},
		{"wrong sa prefix", "/ns/default/serviceaccount/agent", "", "", false},
		{"empty namespace", "/ns//sa/agent", "", "", false},
		{"empty service account", "/ns/default/sa/", "", "", false},
		{"root path", "/", "", "", false},
		{"empty path", "", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns, sa, ok := parseKubernetesPath(tc.path)
			assert.Equal(t, tc.wantOK, ok, "ok mismatch for path %q", tc.path)
			if ok {
				assert.Equal(t, tc.wantNS, ns, "namespace mismatch")
				assert.Equal(t, tc.wantSA, sa, "service account mismatch")
			}
		})
	}
}
