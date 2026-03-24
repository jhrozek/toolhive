// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ory/fosite"

	"github.com/stacklok/toolhive/pkg/authserver/server/registration"
	"github.com/stacklok/toolhive/pkg/authserver/storage"
)

// internalClientSecret is a per-process random secret used for SPIFFE-authenticated clients.
//
// PoC shortcut: fosite's built-in client authentication requires a client_secret for
// confidential clients. Since SPIFFE clients authenticate via mTLS (not secrets), we
// register them with this random secret and inject it into the request form so fosite's
// client_secret_post authentication succeeds. The real authentication has already
// happened at the TLS layer.
//
// The secret is randomized per process instance so it cannot be guessed by an attacker
// who can reach the token endpoint without mTLS. Registered clients become invalid on
// restart (in-memory storage is cleared anyway).
//
// Production would use a custom fosite.ClientAuthenticationStrategy that recognizes
// mTLS-authenticated clients and skips secret validation.
var internalClientSecret = generateRandomSecret() //nolint:gosec // G101: not a credential, see comment above

func generateRandomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ClientAuthPreHandler returns an HTTP handler that performs SPIFFE client
// authentication before delegating to the wrapped handler.
//
// When a SPIFFE ID is present in the request context (set by the SPIFFE middleware
// from the client's TLS certificate):
//  1. Reads client_id from the form body; if absent, uses the SPIFFE ID as client_id
//  2. Validates that client_id matches the SPIFFE ID (per draft-ietf-oauth-spiffe-client-auth)
//  3. Looks up the client in storage; if not found, auto-registers it
//  4. Injects the dummy client_secret so fosite's built-in authentication succeeds
//
// When no SPIFFE ID is in the context (browser OAuth flow), the request passes
// through to the wrapped handler unchanged.
func ClientAuthPreHandler(stor storage.Storage, scopesSupported, allowedAudiences []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spiffeID, ok := SPIFFEIDFromContext(r.Context())
		if !ok {
			// No SPIFFE ID in context — browser OAuth flow. Pass through.
			next.ServeHTTP(w, r)
			return
		}

		// Parse the form to access client_id (idempotent if already parsed).
		if err := r.ParseForm(); err != nil {
			slog.Warn("failed to parse form in SPIFFE client auth pre-handler",
				"error", err,
			)
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"malformed request body")
			return
		}

		clientID := r.Form.Get("client_id")
		spiffeIDStr := spiffeID.String()

		// If client_id is absent, use the SPIFFE ID as the client identifier.
		if clientID == "" {
			clientID = spiffeIDStr
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
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
				"client_id does not match the SPIFFE ID in the client certificate")
			return
		}

		// Ensure the client is registered in storage.
		if err := ensureClientRegistered(r, stor, clientID, scopesSupported, allowedAudiences); err != nil {
			slog.Error("failed to ensure SPIFFE client registration",
				"client_id", clientID,
				"error", err,
			)
			writeOAuthError(w, http.StatusInternalServerError, "server_error",
				"failed to register SPIFFE client")
			return
		}

		// Inject the dummy secret so fosite's client_secret_post authentication
		// succeeds. The real authentication already happened at the TLS layer.
		// Both Form and PostForm must be set because fosite reads r.PostForm
		// directly (see fosite access_request_handler.go).
		r.Form.Set("client_secret", internalClientSecret)
		r.PostForm.Set("client_secret", internalClientSecret)

		slog.Debug("SPIFFE client authenticated via mTLS",
			"client_id", clientID,
		)

		next.ServeHTTP(w, r)
	})
}

// ensureClientRegistered looks up the client in storage and auto-registers it
// if not found. This handles the TOCTOU race by catching ErrAlreadyExists on
// registration and treating it as success.
func ensureClientRegistered(r *http.Request, stor storage.Storage, clientID string, scopesSupported, allowedAudiences []string) error {
	ctx := r.Context()

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
	slog.Debug("auto-registering SPIFFE client",
		"client_id", clientID,
	)

	client, err := registration.New(registration.Config{
		ID:            clientID,
		Secret:        internalClientSecret,
		Public:        false, // Confidential client, authenticated via mTLS
		GrantTypes:    []string{"client_credentials"},
		ResponseTypes: []string{}, // No authorization endpoint
		Scopes:        scopesSupported,
		Audience:      allowedAudiences,
	})
	if err != nil {
		return err
	}

	if err := stor.RegisterClient(ctx, client); err != nil {
		// Handle TOCTOU race: another request may have registered the client
		// between our GetClient check and this RegisterClient call.
		if errors.Is(err, storage.ErrAlreadyExists) {
			slog.Debug("SPIFFE client already registered (concurrent registration)",
				"client_id", clientID,
			)
			return nil
		}
		return err
	}

	slog.Debug("SPIFFE client registered successfully",
		"client_id", clientID,
	)
	return nil
}
