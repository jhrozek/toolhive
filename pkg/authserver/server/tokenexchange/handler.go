// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package tokenexchange

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"

	"github.com/stacklok/toolhive/pkg/authserver/server/session"
	"github.com/stacklok/toolhive/pkg/authserver/spiffe"
)

// RFC 8693 grant type and token type URIs.
const (
	// GrantTypeTokenExchange is the grant_type value for RFC 8693 token exchange.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // not a credential

	// TokenTypeAccessToken is the RFC 8693 token type URI for access tokens.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // not a credential

	// TokenTypeJWT is the RFC 8693 token type URI for JWT tokens.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt" //nolint:gosec // not a credential
)

// Compile-time check that Handler implements fosite.TokenEndpointHandler.
var _ fosite.TokenEndpointHandler = (*Handler)(nil)

// Handler implements RFC 8693 token exchange for SPIFFE-authenticated agents.
//
// When a SPIFFE-authenticated agent presents a user's JWT as subject_token,
// the handler validates the token and issues a delegated JWT with sub=user
// and an act claim containing the agent's SPIFFE ID. This enables user-to-agent
// delegation per RFC 8693 Section 4.1.
type Handler struct {
	*oauth2.HandleHelper
	validator          *SubjectTokenValidator
	delegationLifespan time.Duration
	config             tokenExchangeConfig
}

// tokenExchangeConfig defines the configuration interface needed by the handler.
type tokenExchangeConfig interface {
	fosite.ScopeStrategyProvider
	fosite.AudienceStrategyProvider
	fosite.AccessTokenLifespanProvider
}

// CanHandleTokenEndpointRequest returns true if the request's grant_type is
// the RFC 8693 token exchange grant type.
func (*Handler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(GrantTypeTokenExchange)
}

// CanSkipClientAuth returns false because SPIFFE mTLS authentication is required
// for all token exchange requests.
func (*Handler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

// HandleTokenEndpointRequest validates the token exchange request parameters,
// verifies the subject token, and constructs a delegated session with the act claim.
//
// The delegated token's lifetime is the minimum of the subject token's remaining
// lifetime and the configured delegation lifespan.
func (h *Handler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	client := requester.GetClient()

	// The client MUST be confidential — SPIFFE mTLS clients are never public.
	if client.IsPublic() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(
			"The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'token-exchange'."))
	}

	// Extract the SPIFFE ID from the context. Token exchange requires mTLS authentication
	// so the SPIFFE ID must be present.
	spiffeID, ok := spiffe.SPIFFEIDFromContext(ctx)
	if !ok {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange requires SPIFFE mTLS authentication."))
	}

	form := requester.GetRequestForm()

	// Validate required RFC 8693 parameters.
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"The 'subject_token' parameter is required for token exchange."))
	}

	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"The 'subject_token_type' parameter is required for token exchange."))
	}

	if subjectTokenType != TokenTypeAccessToken && subjectTokenType != TokenTypeJWT {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"The 'subject_token_type' value %q is not supported. Use %q or %q.",
			subjectTokenType, TokenTypeAccessToken, TokenTypeJWT))
	}

	// Reject actor_token parameters — the acting party identity is derived
	// exclusively from the SPIFFE mTLS client certificate, not from a token.
	if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"The 'actor_token' and 'actor_token_type' parameters are not supported. " +
				"Actor identity is derived from the SPIFFE mTLS client certificate."))
	}

	// Validate the subject token against the server's own JWKS.
	validatedClaims, err := h.validator.Validate(ctx, subjectToken)
	if err != nil {
		slog.Debug("Subject token validation failed",
			"error", err,
			"spiffe_id", spiffeID.String(),
		)
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(
			"The subject token is invalid or could not be verified.").WithWrap(err))
	}

	// Validate that each requested scope is allowed for this client.
	for _, scope := range requester.GetRequestedScopes() {
		if !h.config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf(
				"The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
		requester.GrantScope(scope)
	}

	// Validate that the requested audience is allowed for this client.
	if err := h.config.GetAudienceStrategy(ctx)(client.GetAudience(), requester.GetRequestedAudience()); err != nil {
		return errorsx.WithStack(err)
	}
	for _, aud := range requester.GetRequestedAudience() {
		requester.GrantAudience(aud)
	}

	// Build the delegated session with the user's identity and the agent's act claim.
	clientID := client.GetID()
	delegatedSession := session.New(
		validatedClaims.Subject,
		"", // No IDP session link for delegated tokens.
		clientID,
		session.UserClaims{
			Name:  validatedClaims.Name,
			Email: validatedClaims.Email,
		},
	)

	// Add the RFC 8693 Section 4.1 "act" claim identifying the acting party (agent).
	delegatedSession.JWTClaims.Extra["act"] = map[string]interface{}{
		"sub": spiffeID.String(),
	}

	// Compute the delegated token lifetime: the shorter of the subject token's
	// remaining lifetime and the configured delegation lifespan.
	lifetime, err := h.computeLifetime(validatedClaims.Expiry)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(
			"The subject token has expired.").WithWrap(err))
	}
	delegatedSession.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(lifetime))

	requester.SetSession(delegatedSession)

	slog.Debug("Token exchange request validated",
		"subject", validatedClaims.Subject,
		"agent", spiffeID.String(),
		"lifetime", lifetime.String(),
	)

	return nil
}

// PopulateTokenEndpointResponse issues the delegated access token and sets
// the RFC 8693 issued_token_type in the response.
func (h *Handler) PopulateTokenEndpointResponse(
	ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder,
) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has(GrantTypeTokenExchange) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint(
			"The OAuth 2.0 Client is not allowed to use authorization grant 'token-exchange'."))
	}

	// Use the session's ExpiresAt (set during HandleTokenEndpointRequest) as the
	// authoritative lifetime. This respects the min(subject_remaining, delegation)
	// bound computed earlier. Fall back to the configured access token lifespan
	// only if no expiry was set on the session.
	atLifespan := h.config.GetAccessTokenLifespan(ctx)
	if sessionExpiry := requester.GetSession().GetExpiresAt(fosite.AccessToken); !sessionExpiry.IsZero() {
		remaining := time.Until(sessionExpiry)
		if remaining > 0 && remaining < atLifespan {
			atLifespan = remaining
		}
	}

	if _, err := h.IssueAccessToken(ctx, atLifespan, requester, responder); err != nil {
		return err
	}

	// Per RFC 8693 Section 2.2.1, the response MUST include issued_token_type.
	responder.SetExtra("issued_token_type", TokenTypeAccessToken)

	return nil
}

// computeLifetime returns the minimum of the subject token's remaining lifetime
// and the configured delegation lifespan. If the subject token has no expiry,
// the delegation lifespan is used as-is. Returns an error if the subject token
// has already expired.
func (h *Handler) computeLifetime(subjectExpiry time.Time) (time.Duration, error) {
	if subjectExpiry.IsZero() {
		return h.delegationLifespan, nil
	}

	remaining := time.Until(subjectExpiry)
	if remaining <= 0 {
		return 0, fmt.Errorf("subject token expired %v ago", -remaining)
	}

	if remaining < h.delegationLifespan {
		return remaining, nil
	}
	return h.delegationLifespan, nil
}
