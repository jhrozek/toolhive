// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package proxy implements an HTTP reverse proxy for the SPIFFE
// delegation sidecar. It sits on localhost, receives MCP calls from
// an unmodified agent, exchanges the Bearer token for a delegated JWT
// via a TokenExchanger, and forwards the request to the upstream MCP
// server over mTLS.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	// delegatedTokenKey is the context key for the delegated JWT passed
	// from the handler to the reverse proxy Rewrite function.
	delegatedTokenKey contextKey = iota
)

// TokenExchanger exchanges a user token for a delegated token.
type TokenExchanger interface {
	Exchange(ctx context.Context, userToken string) (string, error)
}

// jsonError is the JSON structure returned for error responses.
type jsonError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Proxy is an HTTP reverse proxy that intercepts MCP requests from a
// local agent, exchanges the Bearer token for a delegated JWT via the
// TokenExchanger, and forwards the request to the upstream MCP server.
type Proxy struct {
	listenAddr string
	upstream   *url.URL
	exchanger  TokenExchanger
	tlsConfig  *tls.Config
	server     *http.Server
	revProxy   *httputil.ReverseProxy
	logger     *slog.Logger
}

// New creates a Proxy that listens on listenAddr, exchanges tokens
// using the given TokenExchanger, and forwards requests to upstreamURL
// using the provided TLS configuration for mTLS.
func New(listenAddr string, upstreamURL string, exchanger TokenExchanger, tlsConfig *tls.Config) (*Proxy, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}

	p := &Proxy{
		listenAddr: listenAddr,
		upstream:   u,
		exchanger:  exchanger,
		tlsConfig:  tlsConfig,
		logger:     slog.Default().With("component", "proxy"),
	}

	p.revProxy = &httputil.ReverseProxy{
		Rewrite: p.rewrite,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		ErrorHandler: p.errorHandler,
	}

	return p, nil
}

// Start begins serving HTTP requests. It blocks until the context is
// cancelled, at which point it performs a graceful shutdown. The
// returned error is nil if the server shut down cleanly due to context
// cancellation.
func (p *Proxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", p.handleHealthz)
	mux.HandleFunc("/", p.handleProxy)

	p.server = &http.Server{
		Addr:    p.listenAddr,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		p.logger.Info("starting proxy", "listen", p.listenAddr, "upstream", p.upstream.String())
		if err := p.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server failed: %w", err)
	case <-ctx.Done():
		p.logger.Info("shutting down proxy")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*1e9) // 5 seconds
		defer cancel()
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown failed: %w", err)
		}
		return nil
	}
}

// Shutdown gracefully stops the proxy server.
func (p *Proxy) Shutdown(ctx context.Context) error {
	if p.server == nil {
		return nil
	}
	return p.server.Shutdown(ctx)
}

// handleHealthz responds with a 200 OK and a JSON health status.
func (*Proxy) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Static response, error is unlikely on a memory buffer.
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleProxy extracts the Bearer token, exchanges it for a delegated
// JWT, and forwards the request through the reverse proxy.
func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	userToken, ok := extractBearerToken(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid Bearer token")
		return
	}

	delegated, err := p.exchanger.Exchange(r.Context(), userToken)
	if err != nil {
		p.logger.Debug("token exchange failed", "error", err)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "token exchange failed")
		return
	}

	// Store the delegated token in the request context so the Rewrite
	// function can retrieve it without per-request proxy allocation.
	ctx := context.WithValue(r.Context(), delegatedTokenKey, delegated)
	p.revProxy.ServeHTTP(w, r.WithContext(ctx))
}

// rewrite is the httputil.ReverseProxy Rewrite function. It sets the
// upstream URL, replaces the Authorization header with the delegated
// token, and preserves all other headers.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(p.upstream)
	pr.SetXForwarded()
	pr.Out.URL.Path = pr.In.URL.Path
	pr.Out.URL.RawPath = pr.In.URL.RawPath

	// Always scrub the original Authorization header to prevent the
	// user's raw token from leaking to upstream.
	pr.Out.Header.Del("Authorization")

	// Inject the delegated token from the context.
	if tok, ok := pr.Out.Context().Value(delegatedTokenKey).(string); ok {
		pr.Out.Header.Set("Authorization", "Bearer "+tok)
	}
}

// errorHandler is called when the reverse proxy encounters an error
// communicating with the upstream server.
func (p *Proxy) errorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	p.logger.Debug("upstream error", "error", err)
	writeJSONError(w, http.StatusBadGateway, "bad_gateway", "upstream server error")
}

// extractBearerToken parses "Authorization: Bearer <token>" from the
// request. It returns the token and true if valid, or empty and false
// if the header is missing or malformed.
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}

	// RFC 7235: auth scheme is case-insensitive.
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}

	token := strings.TrimPrefix(auth, prefix)
	if token == "" {
		return "", false
	}

	return token, true
}

// writeJSONError writes a JSON error response with the given HTTP status
// code, error code, and description.
func writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := jsonError{
		Error:            errCode,
		ErrorDescription: description,
	}
	// Encoding to a ResponseWriter is unlikely to fail; ignore the error.
	_ = json.NewEncoder(w).Encode(resp)
}
