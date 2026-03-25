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

package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"

	"github.com/stacklok/toolhive/pkg/authserver/server"
	"github.com/stacklok/toolhive/pkg/authserver/spiffe"
	"github.com/stacklok/toolhive/pkg/authserver/storage"
	"github.com/stacklok/toolhive/pkg/authserver/upstream"
)

// NamedUpstream pairs a logical provider name with its IdentityProvider implementation.
// The name is used as the storage key and must be unique within the upstream slice.
// The Provider field accepts any IdentityProvider: redirect-flow (OIDC/OAuth2) or
// direct-assertion (SPIFFE). Handlers type-assert to the specific sub-interface
// when they need flow-specific methods (e.g., AuthorizationURL, ExchangeCodeForIdentity).
type NamedUpstream struct {
	Name     string
	Provider upstream.IdentityProvider
}

// Handler provides HTTP handlers for the OAuth authorization server endpoints.
type Handler struct {
	provider           fosite.OAuth2Provider
	config             *server.AuthorizationServerConfig
	storage            storage.Storage
	upstreams          []NamedUpstream
	userResolver       *UserResolver
	spiffeClientPolicy *spiffe.ClientPolicy
}

// NewHandler creates a new Handler with the given dependencies.
// upstreams defines the ordered sequence of upstream providers consulted
// during multi-upstream authorization flows (e.g., sequential token acquisition).
// upstreams may be empty for SPIFFE-only deployments where only the
// client_credentials grant is needed (no human login flows).
// spiffePolicy controls which SPIFFE IDs are allowed to auto-register as OAuth clients.
// When nil, all SPIFFE IDs are allowed (backward compatible).
//
// Returns an error if any upstream entry has an empty name or nil provider.
func NewHandler(
	provider fosite.OAuth2Provider,
	config *server.AuthorizationServerConfig,
	stor storage.Storage,
	upstreams []NamedUpstream,
	spiffePolicy *spiffe.ClientPolicy,
) (*Handler, error) {
	for _, u := range upstreams {
		if u.Name == "" {
			return nil, fmt.Errorf("handlers: upstream entry has empty name")
		}
		if u.Provider == nil {
			return nil, fmt.Errorf("handlers: upstream %q has nil provider", u.Name)
		}
	}
	return &Handler{
		provider:           provider,
		config:             config,
		storage:            stor,
		upstreams:          upstreams,
		userResolver:       NewUserResolver(stor),
		spiffeClientPolicy: spiffePolicy,
	}, nil
}

// Routes returns a router with all OAuth/OIDC endpoints registered.
func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	h.OAuthRoutes(r)
	h.WellKnownRoutes(r)
	return r
}

// OAuthRoutes registers OAuth endpoints (authorize, callback, token, register) on the provided router.
// The token endpoint is wrapped with a SPIFFE client authentication pre-handler that
// auto-registers mTLS-authenticated SPIFFE clients before fosite processes the request.
func (h *Handler) OAuthRoutes(r chi.Router) {
	r.Get("/oauth/authorize", h.AuthorizeHandler)
	r.Get("/oauth/callback", h.CallbackHandler)

	// Wrap the token endpoint with SPIFFE client auth so that mTLS-authenticated
	// agents using client_credentials are auto-registered and their dummy secret
	// is injected before fosite's built-in client authentication runs.
	tokenHandler := spiffe.ClientAuthPreHandler(
		h.storage,
		h.config.ScopesSupported,
		h.config.AllowedAudiences,
		h.spiffeClientPolicy,
		http.HandlerFunc(h.TokenHandler),
	)
	r.Post("/oauth/token", tokenHandler.ServeHTTP)

	r.Post("/oauth/register", h.RegisterClientHandler)
}

// WellKnownRoutes registers well-known endpoints (JWKS, OAuth/OIDC discovery) on the provided router.
// Both discovery endpoints are registered per the MCP specification requirement to provide
// at least one discovery mechanism, with both supported for maximum interoperability:
// - /.well-known/oauth-authorization-server (RFC 8414) for OAuth-only clients
// - /.well-known/openid-configuration (OIDC Discovery 1.0) for OIDC clients
//
// The wildcard variants (/.well-known/oauth-authorization-server/*) handle RFC 8414
// Section 3.1 path-based issuers, where clients insert /.well-known/ before the
// issuer's path component (e.g., /.well-known/oauth-authorization-server/inject-test
// for issuer https://example.com/inject-test).
func (h *Handler) WellKnownRoutes(r chi.Router) {
	r.Get("/.well-known/jwks.json", h.JWKSHandler)
	r.Get("/.well-known/oauth-authorization-server", h.OAuthDiscoveryHandler)
	r.Get("/.well-known/oauth-authorization-server/*", h.OAuthDiscoveryHandler)
	r.Get("/.well-known/openid-configuration", h.OIDCDiscoveryHandler)
	r.Get("/.well-known/openid-configuration/*", h.OIDCDiscoveryHandler)
}

// nextMissingUpstream returns the name of the next redirect-flow upstream
// provider in the authorization chain that does not yet have stored tokens
// for this session. Direct-assertion providers (e.g., SPIFFE) are skipped
// because they resolve identity from the request context, not via redirects.
// Returns empty string if all redirect-flow upstreams are satisfied.
// Returns an error if the storage lookup fails.
func (h *Handler) nextMissingUpstream(ctx context.Context, sessionID string) (string, error) {
	stored, err := h.storage.GetAllUpstreamTokens(ctx, sessionID)
	if err != nil {
		return "", fmt.Errorf("failed to check upstream token state: %w", err)
	}
	for _, u := range h.upstreams {
		// Skip non-redirect providers — they don't participate in the
		// browser redirect chain and have no storable tokens.
		if _, ok := u.Provider.(upstream.RedirectFlowProvider); !ok {
			continue
		}
		if _, ok := stored[u.Name]; !ok {
			return u.Name, nil
		}
	}
	return "", nil
}

// upstreamByName returns the upstream provider with the given name.
// It follows the (value, bool) convention: the second return value is false
// if no upstream with that name exists.
func (h *Handler) upstreamByName(name string) (upstream.IdentityProvider, bool) {
	for i := range h.upstreams {
		if h.upstreams[i].Name == name {
			return h.upstreams[i].Provider, true
		}
	}
	return nil, false
}

// redirectProviderByName returns the redirect-flow provider with the given name.
// Returns an error if the provider exists but does not support redirect flows.
func (h *Handler) redirectProviderByName(name string) (upstream.RedirectFlowProvider, error) {
	provider, ok := h.upstreamByName(name)
	if !ok {
		return nil, fmt.Errorf("upstream provider %q not found", name)
	}
	rfp, ok := provider.(upstream.RedirectFlowProvider)
	if !ok {
		return nil, fmt.Errorf("upstream provider %q does not support redirect flows", name)
	}
	return rfp, nil
}
