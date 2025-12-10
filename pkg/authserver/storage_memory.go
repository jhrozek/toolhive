package authserver

import (
	"context"
	"sync"
	"time"

	"github.com/ory/fosite"
)

// MemoryStorage implements the Storage interface with in-memory maps.
// This implementation is thread-safe and suitable for development and testing.
// For production use, consider implementing a persistent storage backend.
type MemoryStorage struct {
	mu sync.RWMutex

	clients       map[string]fosite.Client
	authCodes     map[string]fosite.Requester
	accessTokens  map[string]fosite.Requester
	refreshTokens map[string]fosite.Requester
	pkceRequests  map[string]fosite.Requester
	idpTokens     map[string]*IDPTokens

	// invalidatedCodes tracks auth codes that have been used/invalidated
	invalidatedCodes map[string]bool

	// clientAssertionJWTs tracks JTIs to prevent JWT replay attacks
	clientAssertionJWTs map[string]time.Time
}

// NewMemoryStorage creates a new MemoryStorage instance with initialized maps.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		clients:             make(map[string]fosite.Client),
		authCodes:           make(map[string]fosite.Requester),
		accessTokens:        make(map[string]fosite.Requester),
		refreshTokens:       make(map[string]fosite.Requester),
		pkceRequests:        make(map[string]fosite.Requester),
		idpTokens:           make(map[string]*IDPTokens),
		invalidatedCodes:    make(map[string]bool),
		clientAssertionJWTs: make(map[string]time.Time),
	}
}

// RegisterClient adds or updates a client in the storage.
// This is useful for setting up test clients.
func (s *MemoryStorage) RegisterClient(client fosite.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.GetID()] = client
}

// -----------------------
// fosite.ClientManager
// -----------------------

// GetClient loads the client by its ID or returns an error if the client does not exist.
func (s *MemoryStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, fosite.ErrNotFound.WithHintf("Client with ID '%s' not found", id)
	}
	return client, nil
}

// ClientAssertionJWTValid returns an error if the JTI is known or the DB check failed,
// and nil if the JTI is not known (meaning it can be used).
func (s *MemoryStorage) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if exp, ok := s.clientAssertionJWTs[jti]; ok {
		if time.Now().Before(exp) {
			return fosite.ErrJTIKnown
		}
	}
	return nil
}

// SetClientAssertionJWT marks a JTI as known for the given expiry time.
// Before inserting the new JTI, it will clean up any existing JTIs that have expired.
func (s *MemoryStorage) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean up expired JTIs
	now := time.Now()
	for k, v := range s.clientAssertionJWTs {
		if now.After(v) {
			delete(s.clientAssertionJWTs, k)
		}
	}

	s.clientAssertionJWTs[jti] = exp
	return nil
}

// -----------------------
// oauth2.AuthorizeCodeStorage
// -----------------------

// CreateAuthorizeCodeSession stores the authorization request for a given authorization code.
func (s *MemoryStorage) CreateAuthorizeCodeSession(_ context.Context, code string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authCodes[code] = request
	return nil
}

// GetAuthorizeCodeSession retrieves the authorization request for a given code.
// If the authorization code has been invalidated, it returns ErrInvalidatedAuthorizeCode
// along with the request (as required by fosite).
func (s *MemoryStorage) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, ok := s.authCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound.WithHintf("Authorization code '%s' not found", code)
	}

	// Check if the code has been invalidated
	if s.invalidatedCodes[code] {
		// Must return the request along with the error as per fosite documentation
		return request, fosite.ErrInvalidatedAuthorizeCode
	}

	return request, nil
}

// InvalidateAuthorizeCodeSession marks an authorization code as used/invalid.
// Subsequent calls to GetAuthorizeCodeSession will return ErrInvalidatedAuthorizeCode.
func (s *MemoryStorage) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.authCodes[code]; !ok {
		return fosite.ErrNotFound.WithHintf("Authorization code '%s' not found", code)
	}

	s.invalidatedCodes[code] = true
	return nil
}

// -----------------------
// oauth2.AccessTokenStorage
// -----------------------

// CreateAccessTokenSession stores the access token session.
func (s *MemoryStorage) CreateAccessTokenSession(_ context.Context, signature string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessTokens[signature] = request
	return nil
}

// GetAccessTokenSession retrieves the access token session by its signature.
func (s *MemoryStorage) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, ok := s.accessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound.WithHintf("Access token with signature '%s' not found", signature)
	}
	return request, nil
}

// DeleteAccessTokenSession removes the access token session.
func (s *MemoryStorage) DeleteAccessTokenSession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.accessTokens, signature)
	return nil
}

// -----------------------
// oauth2.RefreshTokenStorage
// -----------------------

// CreateRefreshTokenSession stores the refresh token session.
// The accessSignature parameter is used to link the refresh token to its access token.
func (s *MemoryStorage) CreateRefreshTokenSession(_ context.Context, signature string, _ string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshTokens[signature] = request
	return nil
}

// GetRefreshTokenSession retrieves the refresh token session by its signature.
func (s *MemoryStorage) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, ok := s.refreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound.WithHintf("Refresh token with signature '%s' not found", signature)
	}
	return request, nil
}

// DeleteRefreshTokenSession removes the refresh token session.
func (s *MemoryStorage) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refreshTokens, signature)
	return nil
}

// RotateRefreshToken invalidates a refresh token and all its related token data.
// This is called during token refresh to implement refresh token rotation.
func (s *MemoryStorage) RotateRefreshToken(_ context.Context, requestID string, refreshTokenSignature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Delete the specific refresh token
	delete(s.refreshTokens, refreshTokenSignature)

	// Also delete any access tokens associated with this request ID
	for sig, req := range s.accessTokens {
		if req.GetID() == requestID {
			delete(s.accessTokens, sig)
		}
	}

	return nil
}

// -----------------------
// pkce.PKCERequestStorage
// -----------------------

// CreatePKCERequestSession stores the PKCE request session.
func (s *MemoryStorage) CreatePKCERequestSession(_ context.Context, signature string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pkceRequests[signature] = request
	return nil
}

// GetPKCERequestSession retrieves the PKCE request session by its signature.
func (s *MemoryStorage) GetPKCERequestSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, ok := s.pkceRequests[signature]
	if !ok {
		return nil, fosite.ErrNotFound.WithHintf("PKCE request with signature '%s' not found", signature)
	}
	return request, nil
}

// DeletePKCERequestSession removes the PKCE request session.
func (s *MemoryStorage) DeletePKCERequestSession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.pkceRequests, signature)
	return nil
}

// -----------------------
// IDP Token Storage
// -----------------------

// StoreIDPTokens stores the upstream IDP tokens for a session.
func (s *MemoryStorage) StoreIDPTokens(_ context.Context, sessionID string, tokens *IDPTokens) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.idpTokens[sessionID] = tokens
	return nil
}

// GetIDPTokens retrieves the upstream IDP tokens for a session.
func (s *MemoryStorage) GetIDPTokens(_ context.Context, sessionID string) (*IDPTokens, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens, ok := s.idpTokens[sessionID]
	if !ok {
		return nil, fosite.ErrNotFound.WithHintf("IDP tokens for session '%s' not found", sessionID)
	}
	return tokens, nil
}

// DeleteIDPTokens removes the upstream IDP tokens for a session.
func (s *MemoryStorage) DeleteIDPTokens(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.idpTokens, sessionID)
	return nil
}

// Compile-time interface compliance check
var _ Storage = (*MemoryStorage)(nil)
