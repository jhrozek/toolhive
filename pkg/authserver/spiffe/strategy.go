// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"github.com/stacklok/toolhive/pkg/authserver/server/registration"
	"github.com/stacklok/toolhive/pkg/authserver/storage"
)

// NewClientAuthStrategy returns a fosite.ClientAuthenticationStrategy that
// authenticates SPIFFE mTLS clients.
//
// When a SPIFFE ID is present in the request context (set by the SPIFFE
// middleware from the client's TLS certificate), the strategy:
//  1. Reads client_id from the form; if absent, defaults to the SPIFFE ID
//  2. Validates that client_id matches the SPIFFE ID (per draft-ietf-oauth-spiffe-client-auth)
//  3. Checks the SPIFFE ID against the registration policy (if configured)
//  4. Auto-registers the client in storage if not already present
//  5. Returns the authenticated client
//
// When no SPIFFE ID is in the context (browser OAuth flow), the request is
// delegated to defaultStrategy, preserving standard client authentication.
func NewClientAuthStrategy(
	defaultStrategy fosite.ClientAuthenticationStrategy,
	stor storage.Storage,
	scopesSupported []string,
	allowedAudiences []string,
	policy *ClientPolicy,
) fosite.ClientAuthenticationStrategy {
	return func(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
		spiffeID, ok := SPIFFEIDFromContext(ctx)
		if !ok {
			// No SPIFFE ID in context — browser OAuth flow. Delegate.
			return defaultStrategy(ctx, r, form)
		}

		// Parse the form to access client_id (idempotent if already parsed).
		if err := r.ParseForm(); err != nil {
			return nil, fosite.ErrInvalidRequest.
				WithHint("malformed request body").
				WithWrap(err)
		}

		clientID := form.Get("client_id")
		spiffeIDStr := spiffeID.String()

		// If client_id is absent, default to the SPIFFE ID.
		if clientID == "" {
			clientID = spiffeIDStr
			form.Set("client_id", clientID)
			r.Form.Set("client_id", clientID)
			r.PostForm.Set("client_id", clientID)
		}

		// Validate that the presented client_id matches the SPIFFE ID from the cert.
		// Per draft-ietf-oauth-spiffe-client-auth, the client_id MUST correspond to
		// the SPIFFE ID in the client certificate.
		if clientID != spiffeIDStr {
			slog.Warn("SPIFFE client_id mismatch",
				"client_id", clientID,
				"spiffe_id", spiffeIDStr,
			)
			return nil, fosite.ErrInvalidClient.
				WithHintf("client_id %q does not match SPIFFE ID %q", clientID, spiffeIDStr)
		}

		// Check registration policy before auto-registering.
		if policy != nil && !policy.IsAllowed(spiffeID) {
			slog.Warn("SPIFFE ID denied by registration policy",
				"spiffe_id", spiffeIDStr,
			)
			return nil, fosite.ErrAccessDenied.
				WithHint("SPIFFE ID is not authorized to register as a client")
		}

		// Ensure the client is registered in storage.
		if err := ensureClientRegistered(ctx, stor, clientID, scopesSupported, allowedAudiences, policy); err != nil {
			slog.Error("failed to ensure SPIFFE client registration",
				"client_id", clientID,
				"error", err,
			)
			return nil, fosite.ErrServerError.
				WithHint("failed to register SPIFFE client").
				WithWrap(err)
		}

		// Look up the registered client from storage.
		client, err := stor.GetClient(ctx, clientID)
		if err != nil {
			slog.Error("failed to look up SPIFFE client after registration",
				"client_id", clientID,
				"error", err,
			)
			return nil, fosite.ErrServerError.
				WithHint("failed to look up SPIFFE client").
				WithWrap(err)
		}

		slog.Debug("SPIFFE client authenticated via mTLS",
			"client_id", clientID,
		)

		return client, nil
	}
}

// ensureClientRegistered looks up the client in storage and auto-registers it
// if not found. This handles the TOCTOU race by catching ErrAlreadyExists on
// registration and treating it as success.
//
// When policy is non-nil and MaxRegistrations is set, the policy's registration
// counter is incremented atomically on new registrations.
func ensureClientRegistered(
	ctx context.Context,
	stor storage.Storage,
	clientID string,
	scopesSupported, allowedAudiences []string,
	policy *ClientPolicy,
) error {
	// Check if client already exists.
	_, err := stor.GetClient(ctx, clientID)
	if err == nil {
		// Client exists, nothing to do.
		return nil
	}
	if !errors.Is(err, fosite.ErrNotFound) {
		return err
	}

	// Client not found — auto-register.
	// Check MaxRegistrations before registering.
	if policy != nil && !policy.IncrementRegistrations() {
		slog.Warn("SPIFFE client registration denied: max registrations exceeded",
			"client_id", clientID,
			"max_registrations", policy.MaxRegistrations,
			"current_count", policy.RegistrationCount(),
		)
		return fmt.Errorf("maximum number of client registrations exceeded")
	}

	slog.Debug("auto-registering SPIFFE client",
		"client_id", clientID,
	)

	client, err := registration.New(registration.Config{
		ID:             clientID,
		SkipSecretHash: true,
		Public:         false, // Confidential client, authenticated via mTLS
		GrantTypes:     []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		ResponseTypes:  []string{}, // No authorization endpoint
		Scopes:         scopesSupported,
		Audience:       allowedAudiences,
	})
	if err != nil {
		// Roll back the registration counter — slot was consumed but registration failed.
		if policy != nil {
			policy.DecrementRegistrations()
		}
		return err
	}

	if err := stor.RegisterClient(ctx, client); err != nil {
		// Handle TOCTOU race: another request may have registered the client
		// between our GetClient check and this RegisterClient call.
		if errors.Is(err, storage.ErrAlreadyExists) {
			// Roll back the counter — only one slot should be consumed per client.
			if policy != nil {
				policy.DecrementRegistrations()
			}
			slog.Debug("SPIFFE client already registered (concurrent registration)",
				"client_id", clientID,
			)
			return nil
		}
		// Roll back the counter on unexpected storage errors.
		if policy != nil {
			policy.DecrementRegistrations()
		}
		return err
	}

	slog.Debug("SPIFFE client registered successfully",
		"client_id", clientID,
	)
	return nil
}
