// Copyright 2025 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package upstream provides types and implementations for upstream Identity Provider
// communication in the OAuth authorization server.
//
// # Architecture
//
// The package is designed around a base IdentityProvider interface with two
// specialized sub-interfaces for different authentication ceremonies:
//
//   - IdentityProvider: Base interface (Type method only)
//   - RedirectFlowProvider: Browser-redirect ceremony (AuthorizationURL, ExchangeCodeForIdentity, RefreshTokens)
//   - DirectAssertionProvider: Direct assertion ceremony (ResolveIdentity from request context)
//
// OAuth2Provider is a type alias for RedirectFlowProvider for backward compatibility.
//
// # Type Hierarchy
//
//	IdentityProvider (interface)
//	    ├── RedirectFlowProvider (interface - browser redirect flows)
//	    │       ├── BaseOAuth2Provider (concrete - pure OAuth 2.0, uses userinfo endpoint for identity)
//	    │       └── OIDCProviderImpl (concrete - OIDC with discovery, validates ID tokens for identity)
//	    └── DirectAssertionProvider (interface - direct assertion flows)
//	            └── SPIFFEProvider (concrete - mTLS with SPIFFE ID from X.509-SVID)
//
// # Value Objects
//
//   - Tokens: Token response from upstream IDP
//   - Identity: Combined tokens + subject from code exchange
//   - OAuth2Config: Configuration for OAuth 2.0 providers
//
// # Usage
//
//	config := &upstream.OAuth2Config{
//	    CommonOAuthConfig: upstream.CommonOAuthConfig{
//	        ClientID:     "your-client-id",
//	        ClientSecret: "your-client-secret",
//	        RedirectURI:  "https://your-app.com/callback",
//	        Scopes:       []string{"read", "write"},
//	    },
//	    AuthorizationEndpoint: "https://provider.com/authorize",
//	    TokenEndpoint:         "https://provider.com/token",
//	    UserInfo: &upstream.UserInfoConfig{
//	        EndpointURL: "https://provider.com/userinfo",
//	    },
//	}
//
//	provider, err := upstream.NewOAuth2Provider(config)
//	if err != nil {
//	    return err
//	}
//
//	// Build authorization URL
//	authURL, err := provider.AuthorizationURL(state, pkceChallenge)
//
//	// After callback, exchange code and resolve identity atomically
//	result, err := provider.ExchangeCodeForIdentity(ctx, code, pkceVerifier, nonce)
//	// result.Tokens contains the upstream tokens
//	// result.Subject contains the canonical user identifier
//
// # Extensibility
//
// To add a new IDP type, implement the appropriate sub-interface:
//   - RedirectFlowProvider for browser-based authentication (e.g., SAML)
//   - DirectAssertionProvider for direct identity assertion (e.g., mTLS, workload identity)
//
// # UserInfo Extensibility
//
// The package supports flexible userinfo fetching through UserInfoConfig.
// This enables:
//
//   - Custom field mapping for non-standard provider responses
//   - Additional headers for provider-specific requirements
//
// For custom provider configuration, use UserInfoConfig:
//
//	config := &upstream.UserInfoConfig{
//	    EndpointURL: "https://api.example.com/user",
//	    HTTPMethod:  "GET",  // or "POST" per OIDC Core Section 5.3.1
//	    FieldMapping: &upstream.UserInfoFieldMapping{
//	        SubjectFields: []string{"user_id"},  // custom field for non-OIDC providers
//	    },
//	}
package upstream
