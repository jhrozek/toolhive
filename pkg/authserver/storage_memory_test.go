package authserver

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClient implements fosite.Client for testing.
type mockClient struct {
	id            string
	secret        []byte
	redirectURIs  []string
	grantTypes    []string
	responseTypes []string
	scopes        []string
	public        bool
}

func (c *mockClient) GetID() string                      { return c.id }
func (c *mockClient) GetHashedSecret() []byte            { return c.secret }
func (c *mockClient) GetRedirectURIs() []string          { return c.redirectURIs }
func (c *mockClient) GetGrantTypes() fosite.Arguments    { return c.grantTypes }
func (c *mockClient) GetResponseTypes() fosite.Arguments { return c.responseTypes }
func (c *mockClient) GetScopes() fosite.Arguments        { return c.scopes }
func (c *mockClient) IsPublic() bool                     { return c.public }
func (*mockClient) GetAudience() fosite.Arguments        { return nil }

// mockRequester implements fosite.Requester for testing.
type mockRequester struct {
	id                string
	requestedAt       time.Time
	client            fosite.Client
	requestedScopes   fosite.Arguments
	requestedAudience fosite.Arguments
	grantedScopes     fosite.Arguments
	grantedAudience   fosite.Arguments
	form              url.Values
	session           fosite.Session
}

func newMockRequester(id string, client fosite.Client) *mockRequester {
	return &mockRequester{
		id:                id,
		requestedAt:       time.Now(),
		client:            client,
		requestedScopes:   fosite.Arguments{"openid", "profile"},
		requestedAudience: fosite.Arguments{},
		grantedScopes:     fosite.Arguments{"openid"},
		grantedAudience:   fosite.Arguments{},
		form:              make(url.Values),
		session:           NewSession("test-subject", "test-idp-session"),
	}
}

func (r *mockRequester) SetID(id string)                           { r.id = id }
func (r *mockRequester) GetID() string                             { return r.id }
func (r *mockRequester) GetRequestedAt() time.Time                 { return r.requestedAt }
func (r *mockRequester) GetClient() fosite.Client                  { return r.client }
func (r *mockRequester) GetRequestedScopes() fosite.Arguments      { return r.requestedScopes }
func (r *mockRequester) GetRequestedAudience() fosite.Arguments    { return r.requestedAudience }
func (r *mockRequester) SetRequestedScopes(s fosite.Arguments)     { r.requestedScopes = s }
func (r *mockRequester) SetRequestedAudience(aud fosite.Arguments) { r.requestedAudience = aud }
func (r *mockRequester) AppendRequestedScope(scope string) {
	r.requestedScopes = append(r.requestedScopes, scope)
}
func (r *mockRequester) GetGrantedScopes() fosite.Arguments   { return r.grantedScopes }
func (r *mockRequester) GetGrantedAudience() fosite.Arguments { return r.grantedAudience }
func (r *mockRequester) GrantScope(scope string)              { r.grantedScopes = append(r.grantedScopes, scope) }
func (r *mockRequester) GrantAudience(aud string)             { r.grantedAudience = append(r.grantedAudience, aud) }
func (r *mockRequester) GetSession() fosite.Session           { return r.session }
func (r *mockRequester) SetSession(s fosite.Session)          { r.session = s }
func (r *mockRequester) GetRequestForm() url.Values           { return r.form }
func (*mockRequester) Merge(_ fosite.Requester)               {}
func (r *mockRequester) Sanitize(_ []string) fosite.Requester { return r }

func TestNewMemoryStorage(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	require.NotNil(t, storage)
	assert.NotNil(t, storage.clients)
	assert.NotNil(t, storage.authCodes)
	assert.NotNil(t, storage.accessTokens)
	assert.NotNil(t, storage.refreshTokens)
	assert.NotNil(t, storage.pkceRequests)
	assert.NotNil(t, storage.idpTokens)
	assert.NotNil(t, storage.invalidatedCodes)
	assert.NotNil(t, storage.clientAssertionJWTs)
}

func TestMemoryStorage_RegisterClient(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	client := &mockClient{id: "test-client"}

	storage.RegisterClient(client)

	retrieved, err := storage.GetClient(context.Background(), "test-client")
	require.NoError(t, err)
	assert.Equal(t, client, retrieved)
}

// --- ClientManager Tests ---

func TestMemoryStorage_GetClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		clientID string
		setup    func(*MemoryStorage)
		wantErr  bool
	}{
		{
			name:     "existing client",
			clientID: "test-client",
			setup: func(s *MemoryStorage) {
				s.RegisterClient(&mockClient{id: "test-client"})
			},
			wantErr: false,
		},
		{
			name:     "non-existent client",
			clientID: "non-existent",
			setup:    func(_ *MemoryStorage) {},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage := NewMemoryStorage()
			tt.setup(storage)

			client, err := storage.GetClient(context.Background(), tt.clientID)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, fosite.ErrNotFound)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.clientID, client.GetID())
			}
		})
	}
}

func TestMemoryStorage_ClientAssertionJWT(t *testing.T) {
	t.Parallel()

	t.Run("unknown JTI is valid", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		err := storage.ClientAssertionJWTValid(ctx, "unknown-jti")
		require.NoError(t, err)
	})

	t.Run("known JTI is invalid", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		jti := "test-jti"
		exp := time.Now().Add(time.Hour)
		err := storage.SetClientAssertionJWT(ctx, jti, exp)
		require.NoError(t, err)

		err = storage.ClientAssertionJWTValid(ctx, jti)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrJTIKnown)
	})

	t.Run("expired JTI is valid", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		jti := "expired-jti"
		exp := time.Now().Add(-time.Hour) // Already expired
		err := storage.SetClientAssertionJWT(ctx, jti, exp)
		require.NoError(t, err)

		err = storage.ClientAssertionJWTValid(ctx, jti)
		require.NoError(t, err)
	})

	t.Run("cleanup expired JTIs on set", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		// Add an expired JTI
		storage.mu.Lock()
		storage.clientAssertionJWTs["old-jti"] = time.Now().Add(-time.Hour)
		storage.mu.Unlock()

		// Set a new JTI which should trigger cleanup
		err := storage.SetClientAssertionJWT(ctx, "new-jti", time.Now().Add(time.Hour))
		require.NoError(t, err)

		storage.mu.RLock()
		_, exists := storage.clientAssertionJWTs["old-jti"]
		storage.mu.RUnlock()
		assert.False(t, exists, "expired JTI should have been cleaned up")
	})
}

// --- AuthorizeCodeStorage Tests ---

func TestMemoryStorage_AuthorizeCodeSession(t *testing.T) {
	t.Parallel()

	t.Run("create and get", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		code := "auth-code-123"
		err := storage.CreateAuthorizeCodeSession(ctx, code, request)
		require.NoError(t, err)

		retrieved, err := storage.GetAuthorizeCodeSession(ctx, code, nil)
		require.NoError(t, err)
		assert.Equal(t, request.GetID(), retrieved.GetID())
	})

	t.Run("get non-existent code", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		_, err := storage.GetAuthorizeCodeSession(ctx, "non-existent", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("invalidate code", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		code := "auth-code-to-invalidate"
		err := storage.CreateAuthorizeCodeSession(ctx, code, request)
		require.NoError(t, err)

		err = storage.InvalidateAuthorizeCodeSession(ctx, code)
		require.NoError(t, err)

		// Should still return the request along with the error
		retrieved, err := storage.GetAuthorizeCodeSession(ctx, code, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
		assert.NotNil(t, retrieved, "must return request with invalidated error")
	})

	t.Run("invalidate non-existent code", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		err := storage.InvalidateAuthorizeCodeSession(ctx, "non-existent-code")
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})
}

// --- AccessTokenStorage Tests ---

func TestMemoryStorage_AccessTokenSession(t *testing.T) {
	t.Parallel()

	t.Run("create and get", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		signature := "access-token-sig-123"
		err := storage.CreateAccessTokenSession(ctx, signature, request)
		require.NoError(t, err)

		retrieved, err := storage.GetAccessTokenSession(ctx, signature, nil)
		require.NoError(t, err)
		assert.Equal(t, request.GetID(), retrieved.GetID())
	})

	t.Run("get non-existent token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		_, err := storage.GetAccessTokenSession(ctx, "non-existent", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("delete token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		signature := "access-token-to-delete"
		err := storage.CreateAccessTokenSession(ctx, signature, request)
		require.NoError(t, err)

		err = storage.DeleteAccessTokenSession(ctx, signature)
		require.NoError(t, err)

		_, err = storage.GetAccessTokenSession(ctx, signature, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("delete non-existent token (no error)", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		// Delete should not return error for non-existent tokens
		err := storage.DeleteAccessTokenSession(ctx, "non-existent-token")
		require.NoError(t, err)
	})
}

// --- RefreshTokenStorage Tests ---

func TestMemoryStorage_RefreshTokenSession(t *testing.T) {
	t.Parallel()

	t.Run("create and get", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		signature := "refresh-token-sig-123"
		err := storage.CreateRefreshTokenSession(ctx, signature, "access-sig", request)
		require.NoError(t, err)

		retrieved, err := storage.GetRefreshTokenSession(ctx, signature, nil)
		require.NoError(t, err)
		assert.Equal(t, request.GetID(), retrieved.GetID())
	})

	t.Run("get non-existent token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		_, err := storage.GetRefreshTokenSession(ctx, "non-existent", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("delete token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		signature := "refresh-token-to-delete"
		err := storage.CreateRefreshTokenSession(ctx, signature, "access-sig", request)
		require.NoError(t, err)

		err = storage.DeleteRefreshTokenSession(ctx, signature)
		require.NoError(t, err)

		_, err = storage.GetRefreshTokenSession(ctx, signature, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})
}

func TestMemoryStorage_RotateRefreshToken(t *testing.T) {
	t.Parallel()

	t.Run("rotate deletes refresh and access tokens", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}

		requestID := "request-123"
		request := newMockRequester(requestID, client)

		refreshSig := "refresh-sig-123"
		accessSig := "access-sig-123"

		// Create tokens
		err := storage.CreateRefreshTokenSession(ctx, refreshSig, accessSig, request)
		require.NoError(t, err)
		err = storage.CreateAccessTokenSession(ctx, accessSig, request)
		require.NoError(t, err)

		// Rotate
		err = storage.RotateRefreshToken(ctx, requestID, refreshSig)
		require.NoError(t, err)

		// Both should be deleted
		_, err = storage.GetRefreshTokenSession(ctx, refreshSig, nil)
		assert.ErrorIs(t, err, fosite.ErrNotFound)

		_, err = storage.GetAccessTokenSession(ctx, accessSig, nil)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("rotate non-existent token (no error)", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		err := storage.RotateRefreshToken(ctx, "non-existent-request", "non-existent-sig")
		require.NoError(t, err)
	})
}

// --- PKCERequestStorage Tests ---

func TestMemoryStorage_PKCERequestSession(t *testing.T) {
	t.Parallel()

	t.Run("create and get", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		signature := "pkce-sig-123"
		err := storage.CreatePKCERequestSession(ctx, signature, request)
		require.NoError(t, err)

		retrieved, err := storage.GetPKCERequestSession(ctx, signature, nil)
		require.NoError(t, err)
		assert.Equal(t, request.GetID(), retrieved.GetID())
	})

	t.Run("get non-existent", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		_, err := storage.GetPKCERequestSession(ctx, "non-existent", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()
		client := &mockClient{id: "test-client"}
		request := newMockRequester("req-1", client)

		signature := "pkce-to-delete"
		err := storage.CreatePKCERequestSession(ctx, signature, request)
		require.NoError(t, err)

		err = storage.DeletePKCERequestSession(ctx, signature)
		require.NoError(t, err)

		_, err = storage.GetPKCERequestSession(ctx, signature, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})
}

// --- IDP Token Storage Tests ---

func TestMemoryStorage_IDPTokens(t *testing.T) {
	t.Parallel()

	t.Run("store and get", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		sessionID := "session-123"
		tokens := &IDPTokens{
			AccessToken:  "idp-access-token",
			RefreshToken: "idp-refresh-token",
			IDToken:      "idp-id-token",
			ExpiresAt:    time.Now().Add(time.Hour),
		}

		err := storage.StoreIDPTokens(ctx, sessionID, tokens)
		require.NoError(t, err)

		retrieved, err := storage.GetIDPTokens(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, tokens.AccessToken, retrieved.AccessToken)
		assert.Equal(t, tokens.RefreshToken, retrieved.RefreshToken)
		assert.Equal(t, tokens.IDToken, retrieved.IDToken)
	})

	t.Run("get non-existent", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		_, err := storage.GetIDPTokens(ctx, "non-existent")
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		sessionID := "session-to-delete"
		tokens := &IDPTokens{AccessToken: "test"}
		err := storage.StoreIDPTokens(ctx, sessionID, tokens)
		require.NoError(t, err)

		err = storage.DeleteIDPTokens(ctx, sessionID)
		require.NoError(t, err)

		_, err = storage.GetIDPTokens(ctx, sessionID)
		require.Error(t, err)
		assert.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("overwrite existing tokens", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		storage := NewMemoryStorage()

		sessionID := "session-overwrite"
		tokens1 := &IDPTokens{AccessToken: "token-1"}
		tokens2 := &IDPTokens{AccessToken: "token-2"}

		err := storage.StoreIDPTokens(ctx, sessionID, tokens1)
		require.NoError(t, err)

		err = storage.StoreIDPTokens(ctx, sessionID, tokens2)
		require.NoError(t, err)

		retrieved, err := storage.GetIDPTokens(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, "token-2", retrieved.AccessToken)
	})
}

// --- Concurrent Access Tests ---

func TestMemoryStorage_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("concurrent writes", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		ctx := context.Background()
		client := &mockClient{id: "test-client"}

		var wg sync.WaitGroup
		numGoroutines := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				request := newMockRequester(fmt.Sprintf("req-%d", idx), client)
				code := fmt.Sprintf("code-%d", idx)
				_ = storage.CreateAuthorizeCodeSession(ctx, code, request)
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent reads and writes", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		ctx := context.Background()
		client := &mockClient{id: "test-client"}

		// Pre-populate some data
		for i := 0; i < 10; i++ {
			request := newMockRequester("preload-req", client)
			_ = storage.CreateAccessTokenSession(ctx, fmt.Sprintf("preload-token-%d", i), request)
		}

		var wg sync.WaitGroup
		numGoroutines := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(2)
			// Writer
			go func(idx int) {
				defer wg.Done()
				request := newMockRequester(fmt.Sprintf("req-%d", idx), client)
				_ = storage.CreateAccessTokenSession(ctx, fmt.Sprintf("token-%d", idx), request)
			}(i)
			// Reader
			go func(idx int) {
				defer wg.Done()
				_, _ = storage.GetAccessTokenSession(ctx, fmt.Sprintf("preload-token-%d", idx%10), nil)
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent client registration and lookup", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		ctx := context.Background()

		var wg sync.WaitGroup
		numGoroutines := 50

		for i := 0; i < numGoroutines; i++ {
			wg.Add(2)
			// Register clients
			go func(idx int) {
				defer wg.Done()
				c := &mockClient{id: fmt.Sprintf("client-%d", idx)}
				storage.RegisterClient(c)
			}(i)
			// Look up clients (may or may not exist yet)
			go func(idx int) {
				defer wg.Done()
				_, _ = storage.GetClient(ctx, fmt.Sprintf("client-%d", idx))
			}(i)
		}

		wg.Wait()
	})
}

// --- Interface Compliance Test ---

func TestMemoryStorage_ImplementsStorage(t *testing.T) {
	t.Parallel()

	// This test verifies that MemoryStorage implements the Storage interface
	var _ Storage = (*MemoryStorage)(nil)
}
