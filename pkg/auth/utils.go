// Package auth provides authentication and authorization utilities.
package auth

import (
	"context"
	"net/http"
	"os/user"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stacklok/toolhive/pkg/logger"
)

// GetClaimsFromContext retrieves the claims from the request context.
// This is a helper function that can be used by authorization policies
// to access the claims regardless of which middleware was used (JWT, anonymous, or local).
//
// Returns the claims and a boolean indicating whether claims were found.
func GetClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(ClaimsContextKey{}).(jwt.MapClaims)
	return claims, ok
}

// AuthenticationProvider defines the interface for providing authentication services.
// This interface follows the Single Responsibility Principle by separating concerns:
// - Middleware(): provides request authentication
// - DiscoveryHandler(): provides OAuth discovery metadata (RFC 9728)
type AuthenticationProvider interface {
	// Middleware returns HTTP middleware that authenticates requests
	Middleware() func(http.Handler) http.Handler

	// DiscoveryHandler returns an HTTP handler for OAuth discovery endpoint.
	// Returns nil if discovery is not supported by this provider.
	DiscoveryHandler() http.Handler
}

// JWTAuthenticationProvider implements AuthenticationProvider for JWT-based authentication
type JWTAuthenticationProvider struct {
	validator *TokenValidator
}

// Middleware returns the JWT validation middleware
func (p *JWTAuthenticationProvider) Middleware() func(http.Handler) http.Handler {
	return p.validator.Middleware
}

// DiscoveryHandler returns the OAuth discovery handler
func (p *JWTAuthenticationProvider) DiscoveryHandler() http.Handler {
	return p.validator.AuthInfoHandler()
}

// LocalAuthenticationProvider implements AuthenticationProvider for local user authentication
type LocalAuthenticationProvider struct {
	middleware func(http.Handler) http.Handler
}

// Middleware returns the local user middleware
func (p *LocalAuthenticationProvider) Middleware() func(http.Handler) http.Handler {
	return p.middleware
}

// DiscoveryHandler returns nil as local authentication doesn't support OAuth discovery
func (*LocalAuthenticationProvider) DiscoveryHandler() http.Handler {
	return nil
}

// GetAuthenticationProvider returns the appropriate authentication provider based on the configuration.
// If OIDC config is provided, it returns a JWT provider. Otherwise, it returns a local user provider.
func GetAuthenticationProvider(ctx context.Context, oidcConfig *TokenValidatorConfig,
	allowOpaqueTokens bool) (AuthenticationProvider, error) {
	if oidcConfig != nil {
		logger.Info("OIDC validation enabled")

		// Create JWT validator
		jwtValidator, err := NewTokenValidator(ctx, *oidcConfig, allowOpaqueTokens)
		if err != nil {
			return nil, err
		}

		return &JWTAuthenticationProvider{validator: jwtValidator}, nil
	}

	logger.Info("OIDC validation disabled, using local user authentication")

	// Get current OS user
	currentUser, err := user.Current()
	if err != nil {
		logger.Warnf("Failed to get current user, using 'local' as default: %v", err)
		return &LocalAuthenticationProvider{middleware: LocalUserMiddleware("local")}, nil
	}

	logger.Infof("Using local user authentication for user: %s", currentUser.Username)
	return &LocalAuthenticationProvider{middleware: LocalUserMiddleware(currentUser.Username)}, nil
}
