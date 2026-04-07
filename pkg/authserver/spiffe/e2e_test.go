// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/authserver"
	servercrypto "github.com/stacklok/toolhive/pkg/authserver/server/crypto"
	"github.com/stacklok/toolhive/pkg/authserver/server/keys"
	"github.com/stacklok/toolhive/pkg/authserver/spiffe"
	"github.com/stacklok/toolhive/pkg/authserver/storage"
)

// Cert file paths extracted from a kind cluster.
const (
	serverCertFile = "/tmp/e2e-server.crt"
	serverKeyFile  = "/tmp/e2e-server.key"
	caCertFile     = "/tmp/e2e-ca.crt"
	svidCertFile   = "/tmp/e2e-svid.crt"
	svidKeyFile    = "/tmp/e2e-svid.key"

	expectedSPIFFEID = "spiffe://toolhive.dev/ns/default/sa/test-agent"
	testTrustDomain  = "toolhive.dev"
	testAudience     = "https://test.example.com"
	serverSAN        = "authserver.toolhive-system.svc.cluster.local"
)

// certFiles lists all files required by the E2E tests.
var certFiles = []string{
	serverCertFile, serverKeyFile,
	caCertFile,
	svidCertFile, svidKeyFile,
}

// skipIfCertsMissing skips the test when any required cert file is absent.
func skipIfCertsMissing(t *testing.T) {
	t.Helper()
	for _, f := range certFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Skipf("skipping: cert file %s not found (run from a kind cluster environment)", f)
		}
	}
}

// e2eServer bundles the HTTP server and base URL for a test instance.
type e2eServer struct {
	baseURL   string
	caCertPEM []byte
}

// startE2EServer boots a TLS-enabled auth server using the real certs
// and returns connection details for test clients.
func startE2EServer(t *testing.T, ctx context.Context) *e2eServer {
	t.Helper()

	// Load server TLS cert.
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	require.NoError(t, err, "loading server cert/key")

	// Load CA cert for client verification.
	caCertPEM, err := os.ReadFile(caCertFile)
	require.NoError(t, err, "reading CA cert")
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertPEM), "parsing CA cert")

	// Bind a free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "binding listener")
	addr := listener.Addr().String()

	// Wrap listener with TLS; request (but do not require) client certs
	// so that the no-cert test case can connect.
	//
	// We use RequestClientCert + a custom VerifyPeerCertificate instead of
	// VerifyClientCertIfGiven because the test SVIDs from kind are short-lived
	// (1h) and may have expired between extraction and test execution. The custom
	// verifier validates the chain against the CA but skips time checks.
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Parse the presented certificates.
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
			}
			if len(certs) == 0 {
				return nil // no client cert, allow through
			}
			// Build intermediates from chain (if any).
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediates.AddCert(cert)
			}
			// Verify the chain against the CA, but skip time validation
			// so that recently-expired SVID certs still work.
			_, err := certs[0].Verify(x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				CurrentTime:   certs[0].NotBefore, // pin to cert's own validity window
			})
			return err
		},
	})

	// Build the issuer URL (HTTPS with the CN-based ServerName).
	// The server listens on 127.0.0.1 but clients connect using the
	// real CN as ServerName override in TLS config.
	issuer := "https://" + serverSAN + ":" + portFromAddr(addr)

	// Generate a random HMAC secret for opaque token signing.
	hmacSecret := make([]byte, servercrypto.MinSecretLength)
	_, err = rand.Read(hmacSecret)
	require.NoError(t, err, "generating HMAC secret")

	td, err := spiffeid.TrustDomainFromString(testTrustDomain)
	require.NoError(t, err, "parsing trust domain")

	cfg := authserver.Config{
		Issuer:              issuer,
		KeyProvider:         keys.NewGeneratingProvider("ES256"),
		HMACSecrets:         servercrypto.NewHMACSecrets(hmacSecret),
		AllowedAudiences:    []string{testAudience},
		SPIFFETrustDomain:   td,
		AccessTokenLifespan: time.Hour,
	}

	stor := storage.NewMemoryStorage()

	srv, err := authserver.New(ctx, cfg, stor)
	require.NoError(t, err, "creating auth server")
	t.Cleanup(func() { _ = srv.Close() })

	// Wrap the auth server handler with the SPIFFE middleware.
	handler := spiffe.NewMiddleware(td)(srv.Handler())

	httpServer := &http.Server{
		Handler: handler,
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	})

	go func() {
		if sErr := httpServer.Serve(tlsListener); sErr != nil && sErr != http.ErrServerClosed {
			// Cannot t.Fatal from a goroutine, so just log.
			t.Logf("HTTP server error: %v", sErr)
		}
	}()

	return &e2eServer{
		baseURL:   "https://127.0.0.1:" + portFromAddr(addr),
		caCertPEM: caCertPEM,
	}
}

// portFromAddr extracts the port part from "host:port".
func portFromAddr(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}

// httpClientWithSVID returns an *http.Client configured with the test SVID as
// the client certificate and the CA for server verification.
func httpClientWithSVID(t *testing.T, srv *e2eServer) *http.Client {
	t.Helper()
	svidCert, err := tls.LoadX509KeyPair(svidCertFile, svidKeyFile)
	require.NoError(t, err, "loading SVID cert/key")

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(srv.caCertPEM), "parsing CA cert for client")

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{svidCert},
				RootCAs:      caPool,
				ServerName:   serverSAN,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

// httpClientNoCert returns an *http.Client without a client cert.
func httpClientNoCert(t *testing.T, srv *e2eServer) *http.Client {
	t.Helper()
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(srv.caCertPEM), "parsing CA cert for client (no cert)")

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: serverSAN,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// postTokenForm POSTs a URL-encoded form to /oauth/token and returns the
// raw response.
func postTokenForm(t *testing.T, client *http.Client, baseURL string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(baseURL+"/oauth/token", form)
	require.NoError(t, err, "POST /oauth/token")
	return resp
}

// oauthTokenResponse is the subset of a token response we care about.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// oauthErrorResponse represents an OAuth 2.0 error response body.
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// jwtClaims is a minimal set of JWT claims for verification.
type jwtClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	ClientID string   `json:"client_id"`
}

// decodeJWTPayload extracts and decodes the payload (second segment) of a JWT.
func decodeJWTPayload(t *testing.T, token string) jwtClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT must have 3 segments")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "base64url-decoding JWT payload")

	var claims jwtClaims
	require.NoError(t, json.Unmarshal(payload, &claims), "unmarshalling JWT claims")
	return claims
}

func TestE2ESpiffeClientCredentials(t *testing.T) {
	skipIfCertsMissing(t)

	ctx := context.Background()
	srv := startE2EServer(t, ctx)

	t.Run("happy path - SVID cert + matching client_id", func(t *testing.T) {
		client := httpClientWithSVID(t, srv)

		form := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {expectedSPIFFEID},
			"resource":   {testAudience},
		}

		resp := postTokenForm(t, client, srv.baseURL, form)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "reading response body")

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"expected 200 OK, got %d: %s", resp.StatusCode, string(body))

		var tokenResp oauthTokenResponse
		require.NoError(t, json.Unmarshal(body, &tokenResp), "unmarshalling token response")

		assert.NotEmpty(t, tokenResp.AccessToken, "access_token must not be empty")
		assert.Equal(t, "bearer", strings.ToLower(tokenResp.TokenType), "token_type")
		assert.Greater(t, tokenResp.ExpiresIn, 0, "expires_in must be positive")

		// Decode and verify JWT claims.
		claims := decodeJWTPayload(t, tokenResp.AccessToken)
		assert.Equal(t, expectedSPIFFEID, claims.Subject, "sub claim must be the SPIFFE ID")
		assert.Equal(t, expectedSPIFFEID, claims.ClientID, "client_id claim must be the SPIFFE ID")
		assert.Contains(t, claims.Audience, testAudience, "aud claim must contain the requested resource")
	})

	t.Run("no client cert - fosite rejects (no client auth)", func(t *testing.T) {
		client := httpClientNoCert(t, srv)

		form := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {expectedSPIFFEID},
			"resource":   {testAudience},
		}

		resp := postTokenForm(t, client, srv.baseURL, form)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Without a client cert the SPIFFE middleware is a no-op.
		// Fosite should reject the request because the client is not registered
		// (auto-registration only happens via the SPIFFE pre-handler which requires
		// a SPIFFE ID in context).
		assert.NotEqual(t, http.StatusOK, resp.StatusCode,
			"expected non-200 without client cert, got: %s", string(body))

		var errResp oauthErrorResponse
		require.NoError(t, json.Unmarshal(body, &errResp), "unmarshalling error response")
		assert.NotEmpty(t, errResp.Error, "error field must be present")
	})

	t.Run("mismatched client_id - pre-handler rejects with 401", func(t *testing.T) {
		client := httpClientWithSVID(t, srv)

		form := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"spiffe://toolhive.dev/ns/other/sa/wrong-agent"},
			"resource":   {testAudience},
		}

		resp := postTokenForm(t, client, srv.baseURL, form)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"expected 401 for mismatched client_id, got %d: %s", resp.StatusCode, string(body))

		var errResp oauthErrorResponse
		require.NoError(t, json.Unmarshal(body, &errResp))
		assert.Equal(t, "invalid_client", errResp.Error, "error code")
		assert.Contains(t, errResp.ErrorDescription, "does not match",
			"error_description should mention mismatch")
	})

	t.Run("missing grant_type - fosite rejects with 400", func(t *testing.T) {
		client := httpClientWithSVID(t, srv)

		// Omit grant_type entirely.
		form := url.Values{
			"client_id": {expectedSPIFFEID},
			"resource":  {testAudience},
		}

		resp := postTokenForm(t, client, srv.baseURL, form)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Fosite should return 400 for a missing or invalid grant_type.
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"expected 400 for missing grant_type, got %d: %s", resp.StatusCode, string(body))

		var errResp oauthErrorResponse
		require.NoError(t, json.Unmarshal(body, &errResp))
		assert.NotEmpty(t, errResp.Error, "error field must be present")
	})
}
