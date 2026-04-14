// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package exchanger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	testSPIFFEID    = "spiffe://example.org/agent/test"
	testTrustDomain = "example.org"
	testResource    = "https://api.example.com"
	testAgentToken  = "agent-jwt-xxx"
	testDelegated   = "delegated-jwt-xxx"
	testUserTokenA  = "user-token-alice"
	testUserTokenB  = "user-token-bob"

	//nolint:gosec // G101: test grant type URN, not a credential
	grantTypeExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// mockAuthServer creates an httptest.Server that handles both
// client_credentials and token exchange requests. It returns the
// server, a counter of client_credentials requests, and a counter
// of token exchange requests.
func mockAuthServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	var bootstrapCount, exchangeCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		w.Header().Set("Content-Type", "application/json")

		switch grantType {
		case grantTypeClientCredentials:
			bootstrapCount.Add(1)
			resp := map[string]any{
				"access_token": testAgentToken,
				"expires_in":   3600,
				"token_type":   "Bearer",
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))

		case grantTypeExchange:
			exchangeCount.Add(1)
			// Validate that required fields are present.
			assert.NotEmpty(t, r.FormValue("actor_token"), "actor_token must be present")
			assert.NotEmpty(t, r.FormValue("subject_token"), "subject_token must be present")

			resp := map[string]any{
				"access_token":      testDelegated,
				"expires_in":        900,
				"token_type":        "Bearer",
				"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))

		default:
			http.Error(w, "unsupported grant type", http.StatusBadRequest)
		}
	}))

	t.Cleanup(srv.Close)
	return srv, &bootstrapCount, &exchangeCount
}

func testSpiffeID(t *testing.T) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(testSPIFFEID)
	require.NoError(t, err)
	return id
}

func TestExchanger_Bootstrap(t *testing.T) {
	t.Parallel()

	srv, bootstrapCount, _ := mockAuthServer(t)
	id := testSpiffeID(t)

	exc := New(srv.Client(), id, srv.URL, testResource)

	err := exc.Bootstrap(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(1), bootstrapCount.Load(), "bootstrap should have been called once")

	// Verify the agent token is stored.
	exc.agentTokenMu.RLock()
	defer exc.agentTokenMu.RUnlock()
	require.NotNil(t, exc.agentToken)
	assert.Equal(t, testAgentToken, exc.agentToken.AccessToken)
	assert.Equal(t, "Bearer", exc.agentToken.TokenType)
	assert.False(t, exc.agentToken.Expiry.IsZero(), "expiry should be set")
}

func TestExchanger_Exchange(t *testing.T) {
	t.Parallel()

	srv, _, exchangeCount := mockAuthServer(t)
	id := testSpiffeID(t)

	exc := New(srv.Client(), id, srv.URL, testResource)

	// Bootstrap first.
	require.NoError(t, exc.Bootstrap(context.Background()))

	delegated, err := exc.Exchange(context.Background(), testUserTokenA)
	require.NoError(t, err)
	assert.Equal(t, testDelegated, delegated)
	assert.Equal(t, int32(1), exchangeCount.Load())
}

func TestExchanger_ExchangeCaching(t *testing.T) {
	t.Parallel()

	srv, _, exchangeCount := mockAuthServer(t)
	id := testSpiffeID(t)

	exc := New(srv.Client(), id, srv.URL, testResource)
	require.NoError(t, exc.Bootstrap(context.Background()))

	// First call — should hit the server.
	tok1, err := exc.Exchange(context.Background(), testUserTokenA)
	require.NoError(t, err)
	assert.Equal(t, testDelegated, tok1)
	assert.Equal(t, int32(1), exchangeCount.Load())

	// Second call with the same token — should use cache.
	tok2, err := exc.Exchange(context.Background(), testUserTokenA)
	require.NoError(t, err)
	assert.Equal(t, testDelegated, tok2)
	assert.Equal(t, int32(1), exchangeCount.Load(), "second call should not hit the server")
}

func TestExchanger_ExchangeDifferentUsers(t *testing.T) {
	t.Parallel()

	srv, _, exchangeCount := mockAuthServer(t)
	id := testSpiffeID(t)

	exc := New(srv.Client(), id, srv.URL, testResource)
	require.NoError(t, exc.Bootstrap(context.Background()))

	tok1, err := exc.Exchange(context.Background(), testUserTokenA)
	require.NoError(t, err)
	assert.Equal(t, testDelegated, tok1)

	tok2, err := exc.Exchange(context.Background(), testUserTokenB)
	require.NoError(t, err)
	assert.Equal(t, testDelegated, tok2)

	assert.Equal(t, int32(2), exchangeCount.Load(), "different user tokens should produce separate exchange requests")
}

func TestExchanger_AgentTokenRefresh(t *testing.T) {
	t.Parallel()

	srv, bootstrapCount, exchangeCount := mockAuthServer(t)
	id := testSpiffeID(t)

	exc := New(srv.Client(), id, srv.URL, testResource)

	// Bootstrap normally.
	require.NoError(t, exc.Bootstrap(context.Background()))
	assert.Equal(t, int32(1), bootstrapCount.Load())

	// Expire the agent token by setting its expiry to the past.
	exc.agentTokenMu.Lock()
	exc.agentToken = &oauth2.Token{
		AccessToken: testAgentToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-1 * time.Minute),
	}
	exc.agentTokenMu.Unlock()

	// Exchange should detect the expired agent token and re-bootstrap.
	delegated, err := exc.Exchange(context.Background(), testUserTokenA)
	require.NoError(t, err)
	assert.Equal(t, testDelegated, delegated)

	assert.Equal(t, int32(2), bootstrapCount.Load(), "bootstrap should have been called again for expired agent token")
	assert.Equal(t, int32(1), exchangeCount.Load())
}
