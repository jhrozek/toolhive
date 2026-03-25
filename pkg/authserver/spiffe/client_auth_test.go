// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/authserver/storage"
)

const (
	testSPIFFEID = "spiffe://toolhive.dev/ns/default/sa/test-agent"
)

// stubStorage implements just the ClientRegistry portion of storage.Storage
// needed by ClientAuthPreHandler. All other methods panic if called.
type stubStorage struct {
	storage.Storage // embed to satisfy the interface; unused methods will panic
	clients         map[string]fosite.Client
	registerErr     error
}

func newStubStorage() *stubStorage {
	return &stubStorage{
		clients: make(map[string]fosite.Client),
	}
}

func (s *stubStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, fosite.ErrNotFound
}

func (s *stubStorage) RegisterClient(_ context.Context, client fosite.Client) error {
	if s.registerErr != nil {
		return s.registerErr
	}
	if _, ok := s.clients[client.GetID()]; ok {
		return storage.ErrAlreadyExists
	}
	s.clients[client.GetID()] = client
	return nil
}

// assertNextCalled is a test helper that records whether the next handler was called
// and captures the form values from the request.
type assertNextCalled struct {
	called       bool
	clientID     string
	clientSecret string
}

func (a *assertNextCalled) handler() http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		a.called = true
		a.clientID = r.Form.Get("client_id")
		a.clientSecret = r.Form.Get("client_secret")
	})
}

func TestClientAuthPreHandler_SPIFFEWithMatchingClientID(t *testing.T) {
	stor := newStubStorage()
	next := &assertNextCalled{}
	scopes := []string{"openid", "mcp:tools"}
	audiences := []string{"https://api.example.com"}

	handler := ClientAuthPreHandler(stor, scopes, audiences, nil, next.handler())

	body := strings.NewReader("grant_type=client_credentials&client_id=" + testSPIFFEID)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set SPIFFE ID in context
	spiffeID := spiffeid.RequireFromString(testSPIFFEID)
	req = req.WithContext(ContextWithSPIFFEID(req.Context(), spiffeID))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, next.called, "next handler should have been called")
	assert.Equal(t, testSPIFFEID, next.clientID, "client_id should be the SPIFFE ID")
	assert.Equal(t, internalClientSecret, next.clientSecret, "dummy secret should be injected")

	// Verify client was auto-registered
	client, err := stor.GetClient(context.Background(), testSPIFFEID)
	require.NoError(t, err)
	assert.Equal(t, testSPIFFEID, client.GetID())
	assert.False(t, client.IsPublic(), "SPIFFE client should be confidential")
	assert.True(t, client.GetGrantTypes().Has("client_credentials"), "should have client_credentials grant")
}

func TestClientAuthPreHandler_SPIFFEMismatchedClientID(t *testing.T) {
	stor := newStubStorage()
	next := &assertNextCalled{}

	handler := ClientAuthPreHandler(stor, nil, nil, nil, next.handler())

	body := strings.NewReader("grant_type=client_credentials&client_id=spiffe://evil.com/attacker")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	spiffeID := spiffeid.RequireFromString(testSPIFFEID)
	req = req.WithContext(ContextWithSPIFFEID(req.Context(), spiffeID))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.False(t, next.called, "next handler should NOT have been called")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var errResp oauthError
	err := json.NewDecoder(rr.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_client", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "does not match")
}

func TestClientAuthPreHandler_SPIFFEMissingClientID(t *testing.T) {
	stor := newStubStorage()
	next := &assertNextCalled{}
	scopes := []string{"openid"}
	audiences := []string{"https://api.example.com"}

	handler := ClientAuthPreHandler(stor, scopes, audiences, nil, next.handler())

	// No client_id in the form body — pre-handler should use SPIFFE ID
	body := strings.NewReader("grant_type=client_credentials")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	spiffeID := spiffeid.RequireFromString(testSPIFFEID)
	req = req.WithContext(ContextWithSPIFFEID(req.Context(), spiffeID))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, next.called, "next handler should have been called")
	assert.Equal(t, testSPIFFEID, next.clientID, "client_id should default to SPIFFE ID")
	assert.Equal(t, internalClientSecret, next.clientSecret, "dummy secret should be injected")
}

func TestClientAuthPreHandler_NoSPIFFEID(t *testing.T) {
	stor := newStubStorage()
	next := &assertNextCalled{}

	handler := ClientAuthPreHandler(stor, nil, nil, nil, next.handler())

	// Normal browser OAuth flow — no SPIFFE ID in context
	body := strings.NewReader("grant_type=authorization_code&code=some-code")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, next.called, "next handler should pass through for non-SPIFFE requests")
	// client_secret should NOT be injected for non-SPIFFE requests
	assert.Empty(t, next.clientSecret, "no secret should be injected for non-SPIFFE requests")
}

func TestClientAuthPreHandler_AlreadyRegisteredClient(t *testing.T) {
	stor := newStubStorage()
	// Pre-register the client
	stor.clients[testSPIFFEID] = &fosite.DefaultClient{
		ID:         testSPIFFEID,
		GrantTypes: fosite.Arguments{"client_credentials"},
		Public:     false,
	}

	next := &assertNextCalled{}
	handler := ClientAuthPreHandler(stor, nil, nil, nil, next.handler())

	body := strings.NewReader("grant_type=client_credentials&client_id=" + testSPIFFEID)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	spiffeID := spiffeid.RequireFromString(testSPIFFEID)
	req = req.WithContext(ContextWithSPIFFEID(req.Context(), spiffeID))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, next.called, "next handler should have been called")
	assert.Equal(t, internalClientSecret, next.clientSecret, "dummy secret should be injected")

	// Verify no duplicate registration occurred — still just the one client
	assert.Len(t, stor.clients, 1, "should not create duplicate client")
}

func TestClientAuthPreHandler_ConcurrentRegistration(t *testing.T) {
	stor := newStubStorage()
	// Simulate TOCTOU race: GetClient returns not-found, but RegisterClient
	// returns ErrAlreadyExists because another goroutine registered it first.
	stor.registerErr = storage.ErrAlreadyExists

	next := &assertNextCalled{}
	handler := ClientAuthPreHandler(stor, []string{"openid"}, []string{"https://api.example.com"}, nil, next.handler())

	body := strings.NewReader("grant_type=client_credentials&client_id=" + testSPIFFEID)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	spiffeID := spiffeid.RequireFromString(testSPIFFEID)
	req = req.WithContext(ContextWithSPIFFEID(req.Context(), spiffeID))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, next.called, "next handler should have been called despite TOCTOU race")
	assert.Equal(t, internalClientSecret, next.clientSecret, "dummy secret should be injected")
}
