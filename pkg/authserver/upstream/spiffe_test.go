// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/authserver/spiffe"
)

func TestNewSPIFFEProvider(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	provider := NewSPIFFEProvider(td)

	require.NotNil(t, provider)
	assert.Equal(t, td, provider.trustDomain)
}

func TestSPIFFEProvider_Type(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	provider := NewSPIFFEProvider(td)

	assert.Equal(t, ProviderTypeSPIFFE, provider.Type())
}

func TestSPIFFEProvider_ImplementsDirectAssertionProvider(t *testing.T) {
	t.Parallel()

	// Compile-time check is in spiffe.go, but verify at runtime too
	var _ DirectAssertionProvider = (*SPIFFEProvider)(nil)
}

func TestSPIFFEProvider_ImplementsIdentityProvider(t *testing.T) {
	t.Parallel()

	// Verify SPIFFEProvider satisfies the base interface
	var _ IdentityProvider = (*SPIFFEProvider)(nil)
}

func TestSPIFFEProvider_ResolveIdentity(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	provider := NewSPIFFEProvider(td)

	tests := []struct {
		name       string
		setupCtx   func() context.Context
		wantErr    bool
		errContain string
		wantSub    string
	}{
		{
			name: "success with matching trust domain",
			setupCtx: func() context.Context {
				id := spiffeid.RequireFromString("spiffe://example.org/workload/agent-1")
				return spiffe.ContextWithSPIFFEID(context.Background(), id)
			},
			wantSub: "spiffe://example.org/workload/agent-1",
		},
		{
			name: "success with path containing multiple segments",
			setupCtx: func() context.Context {
				id := spiffeid.RequireFromString("spiffe://example.org/ns/prod/sa/web")
				return spiffe.ContextWithSPIFFEID(context.Background(), id)
			},
			wantSub: "spiffe://example.org/ns/prod/sa/web",
		},
		{
			name: "no SPIFFE ID in context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr:    true,
			errContain: "no SPIFFE ID in context",
		},
		{
			name: "trust domain mismatch",
			setupCtx: func() context.Context {
				id := spiffeid.RequireFromString("spiffe://other-domain.org/workload/agent-1")
				return spiffe.ContextWithSPIFFEID(context.Background(), id)
			},
			wantErr:    true,
			errContain: "trust domain mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.setupCtx()
			identity, err := provider.ResolveIdentity(ctx)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)
				assert.Nil(t, identity)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, identity)
			assert.Equal(t, tt.wantSub, identity.Subject)
			// SPIFFE identities have no tokens
			assert.Nil(t, identity.Tokens)
			// SPIFFE identities have no name or email
			assert.Empty(t, identity.Name)
			assert.Empty(t, identity.Email)
		})
	}
}

func TestSPIFFEProvider_DoesNotImplementRedirectFlowProvider(t *testing.T) {
	t.Parallel()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	provider := NewSPIFFEProvider(td)

	// SPIFFEProvider must NOT satisfy RedirectFlowProvider.
	// This verifies the interface split is correct: SPIFFE providers
	// cannot be used in redirect-flow contexts.
	var ip IdentityProvider = provider
	_, ok := ip.(RedirectFlowProvider)
	assert.False(t, ok, "SPIFFEProvider must not implement RedirectFlowProvider")
}
