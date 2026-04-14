// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package exchanger handles the two-phase token flow for the SPIFFE
// delegation sidecar proxy. It bootstraps the agent's own JWT via a
// client_credentials grant (draft-ietf-oauth-spiffe-client-auth) and
// exchanges incoming user tokens for delegated JWTs using RFC 8693
// token exchange with the agent's JWT as the actor_token.
package exchanger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/stacklok/toolhive/pkg/auth/tokenexchange"
)

const (
	// grantTypeClientCredentials is the OAuth 2.0 client credentials grant type.
	grantTypeClientCredentials = "client_credentials"

	// expiryBuffer is subtracted from token expiry times to avoid using
	// tokens that are about to expire.
	expiryBuffer = 30 * time.Second

	// maxResponseBodySize is the maximum size for reading response bodies (1 MB).
	maxResponseBodySize = 1 << 20
)

// tokenResponse represents the JSON body returned by the token endpoint
// for a client_credentials grant.
type tokenResponse struct {
	AccessToken string `json:"access_token"` //nolint:gosec // G101: field holds token data
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// cachedToken holds a delegated token along with its expiry.
type cachedToken struct {
	token     string
	expiresAt time.Time
}

// Exchanger handles SPIFFE bootstrap and RFC 8693 token exchange for
// the agent proxy. It obtains the agent's own JWT via client_credentials
// grant and exchanges user tokens for delegated JWTs.
type Exchanger struct {
	mtlsClient    *http.Client
	spiffeID      spiffeid.ID
	tokenEndpoint string
	resource      string

	// SubjectTokenType specifies the type of the incoming user token.
	// Common values: "access_token" (default), "id_token", "jwt".
	SubjectTokenType string

	// agentToken is the cached SPIFFE JWT from client_credentials grant.
	agentToken   *oauth2.Token
	agentTokenMu sync.RWMutex

	// delegatedCache maps sha256(userToken) -> cached delegated token.
	delegatedCache sync.Map

	// bootstrapGroup deduplicates concurrent Bootstrap calls.
	bootstrapGroup singleflight.Group
	// exchangeGroup deduplicates concurrent exchanges for the same user token.
	exchangeGroup singleflight.Group

	logger *slog.Logger
}

// New creates an Exchanger that uses the given mTLS client and SPIFFE
// identity to communicate with the authorization server at tokenEndpoint.
// The resource parameter is included in both client_credentials and
// token exchange requests per RFC 8707.
func New(mtlsClient *http.Client, spiffeID spiffeid.ID, tokenEndpoint, resource string) *Exchanger {
	return &Exchanger{
		mtlsClient:       mtlsClient,
		spiffeID:         spiffeID,
		tokenEndpoint:    tokenEndpoint,
		resource:         resource,
		SubjectTokenType: "access_token",
		logger:           slog.Default().With("component", "exchanger"),
	}
}

// Bootstrap performs a client_credentials grant to obtain the agent's own
// SPIFFE JWT. It can be called at startup and again later to refresh an
// expired agent token.
func (e *Exchanger) Bootstrap(ctx context.Context) error {
	form := url.Values{
		"grant_type": {grantTypeClientCredentials},
		"client_id":  {e.spiffeID.String()},
	}
	if e.resource != "" {
		form.Set("resource", e.resource)
	}

	encoded := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenEndpoint, strings.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("creating bootstrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(encoded))

	resp, err := e.mtlsClient.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("failed to close bootstrap response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("reading bootstrap response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Truncate response body to avoid leaking sensitive data in error messages.
		errBody := string(body)
		if len(errBody) > 256 {
			errBody = errBody[:256] + "...(truncated)"
		}
		return fmt.Errorf("bootstrap failed with status %d: %s", resp.StatusCode, errBody)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("parsing bootstrap response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("bootstrap response missing access_token")
	}

	token := &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	e.agentTokenMu.Lock()
	e.agentToken = token
	e.agentTokenMu.Unlock()

	e.logger.Info("bootstrapped SPIFFE agent token", "spiffe_id", e.spiffeID.String())
	return nil
}

// Exchange performs RFC 8693 token exchange for the given user token,
// using the agent's SPIFFE JWT as the actor_token. Results are cached
// by a SHA-256 hash of the user token.
func (e *Exchanger) Exchange(ctx context.Context, userToken string) (string, error) {
	// Check cache first.
	cacheKey := hashToken(userToken)
	if cached, ok := e.delegatedCache.Load(cacheKey); ok {
		ct := cached.(*cachedToken)
		if time.Now().Add(expiryBuffer).Before(ct.expiresAt) {
			return ct.token, nil
		}
		// Expired — remove and proceed with a fresh exchange.
		e.delegatedCache.Delete(cacheKey)
	}

	// Use singleflight to deduplicate concurrent exchanges for the same user token.
	result, err, _ := e.exchangeGroup.Do(cacheKey, func() (interface{}, error) {
		// Re-check cache inside singleflight (another goroutine may have populated it).
		if cached, ok := e.delegatedCache.Load(cacheKey); ok {
			ct := cached.(*cachedToken)
			if time.Now().Add(expiryBuffer).Before(ct.expiresAt) {
				return ct.token, nil
			}
			e.delegatedCache.Delete(cacheKey)
		}

		// Refresh the agent token if expired.
		if err := e.ensureAgentToken(ctx); err != nil {
			return nil, fmt.Errorf("refreshing agent token: %w", err)
		}

		e.agentTokenMu.RLock()
		agentAccessToken := e.agentToken.AccessToken
		e.agentTokenMu.RUnlock()

		subjectTokenType, err := tokenexchange.NormalizeTokenType(e.SubjectTokenType)
		if err != nil {
			return nil, fmt.Errorf("normalizing subject token type: %w", err)
		}

		cfg := &tokenexchange.ExchangeConfig{
			TokenURL: e.tokenEndpoint,
			ClientID: e.spiffeID.String(),
			Resource: e.resource,
			SubjectTokenProvider: func() (string, error) {
				return userToken, nil
			},
			SubjectTokenType: subjectTokenType,
			ActorTokenProvider: func() (string, error) {
				return agentAccessToken, nil
			},
			ActorTokenType: "access_token",
			HTTPClient:     e.mtlsClient,
		}

		token, err := cfg.TokenSource(ctx).Token()
		if err != nil {
			return nil, fmt.Errorf("token exchange failed: %w", err)
		}

		// Cache the delegated token.
		e.delegatedCache.Store(cacheKey, &cachedToken{
			token:     token.AccessToken,
			expiresAt: token.Expiry,
		})

		return token.AccessToken, nil
	})
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

// ensureAgentToken checks whether the agent token is still valid and
// calls Bootstrap to refresh it if necessary. Concurrent callers are
// deduplicated via singleflight to avoid thundering-herd bootstrap requests.
func (e *Exchanger) ensureAgentToken(ctx context.Context) error {
	e.agentTokenMu.RLock()
	token := e.agentToken
	e.agentTokenMu.RUnlock()

	if token == nil || (!token.Expiry.IsZero() && time.Now().Add(expiryBuffer).After(token.Expiry)) {
		_, err, _ := e.bootstrapGroup.Do("bootstrap", func() (interface{}, error) {
			return nil, e.Bootstrap(ctx)
		})
		return err
	}
	return nil
}

// hashToken returns the hex-encoded SHA-256 digest of the given token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
