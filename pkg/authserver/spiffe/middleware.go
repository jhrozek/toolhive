// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// oauthError represents an OAuth 2.0 error response per RFC 6749 Section 5.2.
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// NewMiddleware returns HTTP middleware that extracts and validates a SPIFFE ID
// from the client's TLS certificate.
//
// When a client presents a valid X.509-SVID with a single spiffe:// URI SAN
// matching the expected trust domain, the parsed spiffeid.ID is stored in
// the request context (retrievable via SPIFFEIDFromContext).
//
// When no client certificate is present (e.g., browser OAuth flows), the
// middleware is a no-op and the request passes through unchanged.
//
// When a client certificate IS present but SPIFFE validation fails, the
// middleware returns HTTP 401 with an OAuth-formatted JSON error body.
func NewMiddleware(expectedTD spiffeid.TrustDomain) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No TLS connection or no client certificate presented.
			// This is expected for browser-based OAuth flows where
			// mTLS is not used. Pass through as a no-op.
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			leaf := r.TLS.PeerCertificates[0]

			// Collect SPIFFE URIs from the leaf certificate's URI SANs.
			// Per the X.509-SVID specification (Section 2), a leaf SVID must
			// contain exactly one URI SAN with the "spiffe" scheme. Strictly,
			// the spec says exactly one URI SAN total, but we only enforce
			// exactly one *spiffe://* URI and ignore non-SPIFFE URIs for
			// compatibility with cert-manager which may add additional URIs.
			var spiffeURIs []*url.URL
			for _, uri := range leaf.URIs {
				if uri.Scheme == "spiffe" {
					spiffeURIs = append(spiffeURIs, uri)
				}
			}

			// X.509-SVID Section 2 requires exactly one spiffe:// URI SAN.
			if len(spiffeURIs) == 0 {
				slog.Warn("client certificate has no SPIFFE URI SAN",
					"subject", leaf.Subject.String(),
				)
				writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
					"client certificate does not contain a SPIFFE ID")
				return
			}
			if len(spiffeURIs) > 1 {
				slog.Warn("client certificate has multiple SPIFFE URI SANs",
					"count", len(spiffeURIs),
				)
				writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
					"client certificate contains multiple SPIFFE IDs; exactly one is required")
				return
			}

			// Parse the SPIFFE ID using the go-spiffe library.
			// This validates the URI structure per the SPIFFE ID specification.
			id, err := spiffeid.FromURI(spiffeURIs[0])
			if err != nil {
				slog.Warn("failed to parse SPIFFE ID from certificate",
					"cert_serial", leaf.SerialNumber.String(),
					"error", err,
				)
				writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
					"client certificate contains an invalid SPIFFE ID")
				return
			}

			// Validate the trust domain matches the expected one.
			if id.TrustDomain() != expectedTD {
				slog.Warn("SPIFFE ID trust domain mismatch",
					"presented_td", id.TrustDomain().String(),
				)
				writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
					"SPIFFE ID trust domain does not match expected trust domain")
				return
			}

			// Validate the path does not contain directory traversal segments.
			// The go-spiffe library rejects ".." segments during parsing, so
			// this check is defense-in-depth in case library behavior changes.
			if containsTraversal(id.Path()) {
				slog.Warn("SPIFFE ID path contains directory traversal",
					"spiffe_id", id.String(),
				)
				writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
					"SPIFFE ID path contains invalid traversal segments")
				return
			}

			slog.Debug("extracted SPIFFE ID from client certificate",
				"spiffe_id", id.String(),
			)

			ctx := ContextWithSPIFFEID(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// containsTraversal checks whether a path contains ".." segments.
func containsTraversal(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// writeOAuthError writes an OAuth 2.0-formatted JSON error response.
func writeOAuthError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	// Encoding errors are not recoverable (headers already written), log for diagnostics
	if err := json.NewEncoder(w).Encode(&oauthError{
		Error:            errCode,
		ErrorDescription: description,
	}); err != nil {
		slog.Debug("failed to encode OAuth error response", "error", err)
	}
}
