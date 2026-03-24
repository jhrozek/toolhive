// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTrustDomain = "example.org"

// leafCertWithURIs creates a minimal x509.Certificate with the given URI SANs.
func leafCertWithURIs(uris ...string) *x509.Certificate {
	parsed := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			panic("invalid test URI: " + u)
		}
		parsed = append(parsed, p)
	}
	return &x509.Certificate{
		URIs: parsed,
	}
}

// nextHandlerRecorder returns an http.Handler that records whether it was
// called and captures the SPIFFE ID from the request context.
func nextHandlerRecorder() (http.Handler, *bool, *spiffeid.ID) {
	called := false
	var captured spiffeid.ID
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if id, ok := SPIFFEIDFromContext(r.Context()); ok {
			captured = id
		}
	})
	return h, &called, &captured
}

func TestMiddleware_NoTLS(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	// req.TLS is nil by default
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, *called, "next handler should be called when no TLS")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_TLSNoPeerCerts(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: nil, // TLS but no client cert
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, *called, "next handler should be called when TLS but no client cert")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_ValidSPIFFECert(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, capturedID := nextHandlerRecorder()
	handler := mw(next)

	cert := leafCertWithURIs("spiffe://example.org/workload/my-service")
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, *called, "next handler should be called for valid SPIFFE cert")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "spiffe://example.org/workload/my-service", capturedID.String())
}

func TestMiddleware_NoSPIFFEURI(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	// Certificate with a non-SPIFFE URI SAN
	cert := leafCertWithURIs("https://example.com/identity")
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, *called, "next handler should NOT be called when cert has no SPIFFE URI")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var errResp oauthError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_client", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "does not contain a SPIFFE ID")
}

func TestMiddleware_MultipleSPIFFEURIs(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	cert := leafCertWithURIs(
		"spiffe://example.org/workload/svc-a",
		"spiffe://example.org/workload/svc-b",
	)
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, *called, "next handler should NOT be called with multiple SPIFFE URIs")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var errResp oauthError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_client", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "multiple SPIFFE IDs")
}

func TestMiddleware_WrongTrustDomain(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	// Certificate from a different trust domain
	cert := leafCertWithURIs("spiffe://evil.org/workload/attacker")
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, *called, "next handler should NOT be called with wrong trust domain")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var errResp oauthError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_client", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "trust domain")
}

func TestMiddleware_PathTraversal(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	// The go-spiffe library's spiffeid.FromString rejects ".." in paths,
	// so we verify that the middleware correctly handles this case.
	// Since spiffeid.FromString will return an error for paths with "..",
	// the middleware should reject the cert at the parse stage.
	cert := leafCertWithURIs("spiffe://example.org/workload/../admin")
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, *called, "next handler should NOT be called with path traversal")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var errResp oauthError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_client", errResp.Error)
}

func TestMiddleware_EmptyURISANs(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, _ := nextHandlerRecorder()
	handler := mw(next)

	// Certificate with no URI SANs at all
	cert := &x509.Certificate{}
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.False(t, *called, "next handler should NOT be called when cert has no URI SANs")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_MixedURISANs(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, capturedID := nextHandlerRecorder()
	handler := mw(next)

	// Certificate with one SPIFFE URI and one non-SPIFFE URI
	cert := leafCertWithURIs(
		"https://example.com/identity",
		"spiffe://example.org/workload/my-service",
	)
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Exactly one SPIFFE URI is valid even when other non-SPIFFE URIs are present
	assert.True(t, *called, "next handler should be called when exactly one SPIFFE URI is present")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "spiffe://example.org/workload/my-service", capturedID.String())
}

func TestMiddleware_SPIFFEIDWithNestedPath(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	mw := NewMiddleware(td)

	next, called, capturedID := nextHandlerRecorder()
	handler := mw(next)

	cert := leafCertWithURIs("spiffe://example.org/region/us-east/workload/my-service")
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, *called, "next handler should be called for valid nested path")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "spiffe://example.org/region/us-east/workload/my-service", capturedID.String())
}
