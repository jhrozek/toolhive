// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
// needed by the strategy. All other methods panic if called.
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

// buildRequest creates an http.Request with the given form body and optional
// SPIFFE ID in context.
func buildRequest(t *testing.T, formBody string, spiffeID *spiffeid.ID) (*http.Request, url.Values) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	form := url.Values{}
	for k, v := range req.Form {
		form[k] = v
	}
	if spiffeID != nil {
		req = req.WithContext(ContextWithSPIFFEID(req.Context(), *spiffeID))
	}
	return req, form
}

func TestNewClientAuthStrategy(t *testing.T) {
	spiffeID := spiffeid.RequireFromString(testSPIFFEID)
	scopes := []string{"openid", "mcp:tools"}
	audiences := []string{"https://api.example.com"}

	tests := []struct {
		name string
		// setup
		formBody    string
		withSPIFFE  bool
		preRegister bool // pre-register the client in storage
		registerErr error
		policy      *ClientPolicy
		// expectations
		wantErr         bool
		wantErrIs       *fosite.RFC6749Error
		wantClientID    string
		wantDefaultCall bool // whether the default strategy should be called
		wantFormUpdated bool // whether form values should be updated with SPIFFE ID
	}{
		{
			name:         "SPIFFE ID present, matching client_id",
			formBody:     "grant_type=client_credentials&client_id=" + testSPIFFEID,
			withSPIFFE:   true,
			wantClientID: testSPIFFEID,
		},
		{
			name:       "SPIFFE ID present, mismatched client_id",
			formBody:   "grant_type=client_credentials&client_id=spiffe://evil.com/attacker",
			withSPIFFE: true,
			wantErr:    true,
			wantErrIs:  fosite.ErrInvalidClient,
		},
		{
			name:            "SPIFFE ID present, missing client_id",
			formBody:        "grant_type=client_credentials",
			withSPIFFE:      true,
			wantClientID:    testSPIFFEID,
			wantFormUpdated: true,
		},
		{
			name:       "SPIFFE ID present, denied by policy",
			formBody:   "grant_type=client_credentials&client_id=" + testSPIFFEID,
			withSPIFFE: true,
			policy: &ClientPolicy{
				AllowedIdentities: []AllowedIdentity{
					{Namespace: "production", ServiceAccount: "allowed-only"},
				},
			},
			wantErr:   true,
			wantErrIs: fosite.ErrAccessDenied,
		},
		{
			name:            "No SPIFFE ID delegates to default strategy",
			formBody:        "grant_type=authorization_code&code=some-code",
			withSPIFFE:      false,
			wantDefaultCall: true,
			wantClientID:    "browser-client",
		},
		{
			name:         "Already registered client",
			formBody:     "grant_type=client_credentials&client_id=" + testSPIFFEID,
			withSPIFFE:   true,
			preRegister:  true,
			wantClientID: testSPIFFEID,
		},
		{
			name:         "Concurrent registration (TOCTOU)",
			formBody:     "grant_type=client_credentials&client_id=" + testSPIFFEID,
			withSPIFFE:   true,
			registerErr:  storage.ErrAlreadyExists,
			wantClientID: testSPIFFEID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stor := newStubStorage()
			stor.registerErr = tt.registerErr

			// For the TOCTOU test, we need the client to exist in storage
			// so that the final GetClient succeeds (even though RegisterClient
			// returns ErrAlreadyExists, simulating a concurrent registration).
			if tt.registerErr == storage.ErrAlreadyExists {
				stor.clients[testSPIFFEID] = &fosite.DefaultClient{
					ID:         testSPIFFEID,
					GrantTypes: fosite.Arguments{"client_credentials"},
					Public:     false,
				}
			}

			if tt.preRegister {
				stor.clients[testSPIFFEID] = &fosite.DefaultClient{
					ID:         testSPIFFEID,
					GrantTypes: fosite.Arguments{"client_credentials"},
					Public:     false,
				}
			}

			defaultCalled := false
			mockDefault := func(_ context.Context, _ *http.Request, _ url.Values) (fosite.Client, error) {
				defaultCalled = true
				return &fosite.DefaultClient{ID: "browser-client"}, nil
			}

			var sid *spiffeid.ID
			if tt.withSPIFFE {
				sid = &spiffeID
			}

			req, form := buildRequest(t, tt.formBody, sid)

			strategy := NewClientAuthStrategy(mockDefault, stor, scopes, audiences, tt.policy)
			client, err := strategy(req.Context(), req, form)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					var rfcErr *fosite.RFC6749Error
					require.ErrorAs(t, err, &rfcErr)
					assert.Equal(t, tt.wantErrIs.ErrorField, rfcErr.ErrorField,
						"expected error code %q, got %q", tt.wantErrIs.ErrorField, rfcErr.ErrorField)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)
			assert.Equal(t, tt.wantClientID, client.GetID())
			assert.Equal(t, tt.wantDefaultCall, defaultCalled)

			// Verify SPIFFE-authenticated clients are confidential with expected grants.
			if tt.withSPIFFE {
				assert.False(t, client.IsPublic(), "SPIFFE client should be confidential")
				assert.True(t, client.GetGrantTypes().Has("client_credentials"),
					"should have client_credentials grant")
			}

			// Verify form was updated when client_id was missing.
			if tt.wantFormUpdated {
				assert.Equal(t, testSPIFFEID, form.Get("client_id"),
					"form client_id should be set to SPIFFE ID")
				assert.Equal(t, testSPIFFEID, req.Form.Get("client_id"),
					"r.Form client_id should be set to SPIFFE ID")
				assert.Equal(t, testSPIFFEID, req.PostForm.Get("client_id"),
					"r.PostForm client_id should be set to SPIFFE ID")
			}
		})
	}
}
