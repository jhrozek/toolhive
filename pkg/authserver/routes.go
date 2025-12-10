package authserver

import (
	"log/slog"
	"net/http"

	"github.com/ory/fosite"
)

// Router provides HTTP handlers for the OAuth authorization server endpoints.
type Router struct {
	logger   *slog.Logger
	provider fosite.OAuth2Provider
	config   *OAuth2Config
	storage  Storage
}

// NewRouter creates a new Router with the given dependencies.
func NewRouter(logger *slog.Logger, provider fosite.OAuth2Provider, config *OAuth2Config, storage Storage) *Router {
	if logger == nil {
		logger = slog.Default()
	}

	return &Router{
		logger:   logger,
		provider: provider,
		config:   config,
		storage:  storage,
	}
}

// Routes registers the OAuth/OIDC endpoints on the provided mux.
func (r *Router) Routes(mux *http.ServeMux) {
	// Token endpoint
	mux.HandleFunc("POST /oauth/token", r.TokenHandler)

	// JWKS endpoint
	mux.HandleFunc("GET /.well-known/jwks.json", r.JWKSHandler)

	// OIDC Discovery endpoint
	mux.HandleFunc("GET /.well-known/openid-configuration", r.OIDCDiscoveryHandler)
}
