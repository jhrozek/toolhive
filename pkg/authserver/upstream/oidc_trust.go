// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

// ProviderTypeOIDCTrust is the provider type for OIDC trust-only providers.
const ProviderTypeOIDCTrust ProviderType = "oidc-trust"

// Compile-time check that OIDCTrustProvider implements IdentityProvider.
var _ IdentityProvider = (*OIDCTrustProvider)(nil)

// OIDCTrustProvider provides OIDC discovery and JWKS trust material
// for token exchange validation. It does NOT participate in redirect-based
// authentication flows, so it does not trigger the upstream swap middleware.
type OIDCTrustProvider struct {
	issuerURL        string
	expectedAudience string
	caBundlePath     string
	allowPrivateIP   bool
}

// NewOIDCTrustProvider creates a new OIDC trust-only provider.
// The issuerURL is the OIDC issuer whose JWKS will be used for token validation.
// The expectedAudience is the expected "aud" claim value; it may be empty for
// issuers where audience validation is not required.
// The caBundlePath is optional; when set, it is used to verify the issuer's TLS cert.
// When allowPrivateIP is true, the HTTP client used for OIDC discovery and JWKS
// fetching will permit connections to private IP addresses.
func NewOIDCTrustProvider(issuerURL, expectedAudience, caBundlePath string, allowPrivateIP bool) *OIDCTrustProvider {
	return &OIDCTrustProvider{
		issuerURL:        issuerURL,
		expectedAudience: expectedAudience,
		caBundlePath:     caBundlePath,
		allowPrivateIP:   allowPrivateIP,
	}
}

// Type returns the provider type identifier.
func (*OIDCTrustProvider) Type() ProviderType {
	return ProviderTypeOIDCTrust
}

// IssuerURL returns the OIDC issuer URL for this trust provider.
func (p *OIDCTrustProvider) IssuerURL() string {
	return p.issuerURL
}

// ExpectedAudience returns the expected audience for token validation.
func (p *OIDCTrustProvider) ExpectedAudience() string {
	return p.expectedAudience
}

// CABundlePath returns the CA bundle path for TLS verification of issuer endpoints.
func (p *OIDCTrustProvider) CABundlePath() string {
	return p.caBundlePath
}

// AllowPrivateIP returns whether the HTTP client should permit private IP addresses.
func (p *OIDCTrustProvider) AllowPrivateIP() bool {
	return p.allowPrivateIP
}
