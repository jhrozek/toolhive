package authserver

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/stacklok/toolhive/pkg/logger"
)

// CreateHandlers creates auth server HTTP handlers from RunConfig.
// Returns nil handlers if config is nil or not enabled.
// The proxyPort is used to resolve :0 in the issuer URL.
func CreateHandlers(
	ctx context.Context,
	cfg *RunConfig,
	proxyPort int,
) (oauthMux http.Handler, wellKnownMux http.Handler, err error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil, nil
	}

	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid auth server config: %w", err)
	}

	// Resolve issuer URL - replace :0 with actual port if needed
	issuer := resolveIssuer(cfg.Issuer, proxyPort)

	// Load signing key from file
	rsaKey, err := LoadSigningKey(cfg.SigningKeyPath)
	if err != nil {
		return nil, nil, err
	}

	// Build internal config from RunConfig
	internalConfig, err := cfg.toInternalConfig(issuer, rsaKey)
	if err != nil {
		return nil, nil, err
	}

	// Use existing package functions to create components
	oauth2Config, err := NewOAuth2Config(internalConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OAuth2 config: %w", err)
	}

	storage := NewMemoryStorage()
	registerClients(storage, cfg.Clients)

	provider := createProvider(rsaKey, oauth2Config, storage)

	// Create router with optional upstream
	routerOpts, err := createRouterOpts(ctx, cfg.Upstream, issuer)
	if err != nil {
		return nil, nil, err
	}

	router := NewRouter(slog.Default(), provider, oauth2Config, storage, routerOpts...)

	// Create and populate muxes
	oauthServeMux := http.NewServeMux()
	wellKnownServeMux := http.NewServeMux()
	router.OAuthRoutes(oauthServeMux)
	router.WellKnownRoutes(wellKnownServeMux)

	logger.Infof("Embedded OAuth authorization server configured with issuer: %s", issuer)

	return oauthServeMux, wellKnownServeMux, nil
}

// LoadSigningKey loads an RSA private key from a PEM file.
// Supports both PKCS1 and PKCS8 formats.
func LoadSigningKey(keyPath string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 - keyPath is provided by user via CLI flag or config
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from signing key")
	}

	// Try PKCS1 first
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}

	// Try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not an RSA key")
	}

	return rsaKey, nil
}

// toInternalConfig converts RunConfig to the internal Config struct.
func (c *RunConfig) toInternalConfig(issuer string, rsaKey *rsa.PrivateKey) (*Config, error) {
	accessTokenLifespan := c.AccessTokenLifespan
	if accessTokenLifespan == 0 {
		accessTokenLifespan = time.Hour
	}

	refreshTokenLifespan := c.RefreshTokenLifespan
	if refreshTokenLifespan == 0 {
		refreshTokenLifespan = 24 * time.Hour
	}

	config := &Config{
		Issuer:               issuer,
		AccessTokenLifespan:  accessTokenLifespan,
		RefreshTokenLifespan: refreshTokenLifespan,
		AuthCodeLifespan:     10 * time.Minute,
		Secret:               []byte("dev-secret-must-be-32-bytes-long"),
		PrivateKeys: []PrivateKey{{
			KeyID:     "key-1",
			Algorithm: "RS256",
			Key:       rsaKey,
		}},
	}

	// Configure upstream if present
	if c.Upstream != nil && c.Upstream.Issuer != "" {
		clientSecret, err := c.Upstream.resolveClientSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve upstream client secret: %w", err)
		}

		config.Upstream = UpstreamConfig{
			Issuer:       c.Upstream.Issuer,
			ClientID:     c.Upstream.ClientID,
			ClientSecret: clientSecret,
			Scopes:       c.Upstream.Scopes,
			RedirectURI:  issuer + "/oauth/callback",
		}
	}

	return config, nil
}

// resolveClientSecret returns the client secret, reading from file if needed.
func (c *RunUpstreamConfig) resolveClientSecret() (string, error) {
	if c.ClientSecretFile != "" {
		data, err := os.ReadFile(c.ClientSecretFile) // #nosec G304 - file path is provided by user via config
		if err != nil {
			return "", fmt.Errorf("failed to read client secret file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return c.ClientSecret, nil
}

// resolveIssuer replaces :0 in issuer with actual port.
func resolveIssuer(issuer string, proxyPort int) string {
	if proxyPort > 0 && strings.Contains(issuer, ":0") {
		return strings.Replace(issuer, ":0", fmt.Sprintf(":%d", proxyPort), 1)
	}
	return issuer
}

// registerClients adds clients from config to storage.
func registerClients(storage *MemoryStorage, clients []RunClientConfig) {
	for _, c := range clients {
		client := &fosite.DefaultClient{
			ID:            c.ID,
			RedirectURIs:  c.RedirectURIs,
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			Scopes:        []string{"openid", "profile", "email"},
			Public:        c.Public,
		}
		if !c.Public && c.Secret != "" {
			client.Secret = []byte(c.Secret)
		}
		storage.RegisterClient(client)
	}
}

// createProvider creates a fosite provider with JWT strategy.
func createProvider(rsaKey *rsa.PrivateKey, oauth2Config *OAuth2Config, storage *MemoryStorage) fosite.OAuth2Provider {
	jwtStrategy := compose.NewOAuth2JWTStrategy(
		func(_ context.Context) (interface{}, error) { return rsaKey, nil },
		compose.NewOAuth2HMACStrategy(oauth2Config.Config),
		oauth2Config.Config,
	)

	return compose.Compose(
		oauth2Config.Config,
		storage,
		&compose.CommonStrategy{CoreStrategy: jwtStrategy},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
	)
}

// createRouterOpts creates router options, including upstream provider if configured.
func createRouterOpts(ctx context.Context, upstream *RunUpstreamConfig, issuer string) ([]RouterOption, error) {
	if upstream == nil || upstream.Issuer == "" {
		return nil, nil
	}

	clientSecret, err := upstream.resolveClientSecret()
	if err != nil {
		return nil, err
	}

	upstreamCfg := UpstreamConfig{
		Issuer:       upstream.Issuer,
		ClientID:     upstream.ClientID,
		ClientSecret: clientSecret,
		Scopes:       upstream.Scopes,
		RedirectURI:  issuer + "/oauth/callback",
	}

	upstreamProvider, err := NewOIDCUpstreamProvider(ctx, upstreamCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream provider: %w", err)
	}

	return []RouterOption{WithUpstreamProvider(upstreamProvider)}, nil
}
