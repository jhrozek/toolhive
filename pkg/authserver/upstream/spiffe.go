// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/stacklok/toolhive/pkg/authserver/spiffe"
)

// Compile-time interface compliance check.
var _ DirectAssertionProvider = (*SPIFFEProvider)(nil)

// SPIFFEProvider resolves identity from a SPIFFE ID in the request context.
// The SPIFFE ID is set by the mTLS middleware after validating the client's
// X.509-SVID certificate. This provider performs trust domain validation
// as a defense-in-depth check (the middleware also validates trust domain).
type SPIFFEProvider struct {
	trustDomain spiffeid.TrustDomain
}

// NewSPIFFEProvider creates a new SPIFFE upstream provider for the given trust domain.
func NewSPIFFEProvider(td spiffeid.TrustDomain) *SPIFFEProvider {
	return &SPIFFEProvider{trustDomain: td}
}

// Type returns the provider type identifier.
func (*SPIFFEProvider) Type() ProviderType {
	return ProviderTypeSPIFFE
}

// ResolveIdentity extracts the SPIFFE ID from the request context and returns
// it as an upstream Identity. The SPIFFE ID must have been placed in the context
// by the mTLS middleware. The trust domain is validated as a defense-in-depth
// measure (the middleware also validates it).
func (p *SPIFFEProvider) ResolveIdentity(ctx context.Context) (*Identity, error) {
	spiffeID, ok := spiffe.SPIFFEIDFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no SPIFFE ID in context")
	}

	if spiffeID.TrustDomain() != p.trustDomain {
		return nil, fmt.Errorf("trust domain mismatch: expected %s, got %s",
			p.trustDomain, spiffeID.TrustDomain())
	}

	return &Identity{
		Subject: spiffeID.String(),
		// No tokens for SPIFFE - the X.509-SVID is the credential.
	}, nil
}
