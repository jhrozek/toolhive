// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testUserToken      = "user-token-123"
	testDelegatedToken = "delegated-jwt-456"
)

// mockExchanger implements TokenExchanger for testing.
type mockExchanger struct {
	// exchangeFn is called for each Exchange invocation.
	exchangeFn func(ctx context.Context, userToken string) (string, error)
}

func (m *mockExchanger) Exchange(ctx context.Context, userToken string) (string, error) {
	return m.exchangeFn(ctx, userToken)
}

// newSuccessExchanger returns a mock that maps testUserToken to
// testDelegatedToken and rejects anything else.
func newSuccessExchanger() *mockExchanger {
	return &mockExchanger{
		exchangeFn: func(_ context.Context, userToken string) (string, error) {
			if userToken == testUserToken {
				return testDelegatedToken, nil
			}
			return "", fmt.Errorf("unexpected token: %s", userToken)
		},
	}
}

// newFailingExchanger returns a mock that always returns an error.
func newFailingExchanger() *mockExchanger {
	return &mockExchanger{
		exchangeFn: func(_ context.Context, _ string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		},
	}
}

// startProxy creates and starts a Proxy on a random port, returning
// the proxy's base URL and a cancel function to stop it.
func startProxy(t *testing.T, upstreamURL string, exc TokenExchanger) string {
	t.Helper()

	// Bind to a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()
	// Close the listener — the proxy will re-bind to the same address.
	// There is a small race window but it is acceptable in tests.
	require.NoError(t, ln.Close())

	p, err := New(addr, upstreamURL, exc, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Start(ctx)
	}()

	// Wait until the proxy is accepting connections.
	waitForReady(t, "http://"+addr+"/healthz")

	t.Cleanup(func() {
		cancel()
		// Drain the Start error — should be nil on clean shutdown.
		if err := <-errCh; err != nil {
			t.Logf("proxy start returned error: %v", err)
		}
	})

	return "http://" + addr
}

// waitForReady polls the health endpoint until it returns 200 or the
// test times out.
func waitForReady(t *testing.T, healthURL string) {
	t.Helper()

	for range 100 {
		resp, err := http.Get(healthURL) //nolint:gosec // test code, URL is trusted
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
	t.Fatal("proxy did not become ready")
}

func TestProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		upstream func(t *testing.T) *httptest.Server
		exc      func() TokenExchanger
		request  func(t *testing.T, proxyURL string) *http.Response

		wantStatus int
		verify     func(t *testing.T, resp *http.Response)
	}{
		{
			name: "TokenInjection",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Echo back the Authorization header so the test can verify it.
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte(r.Header.Get("Authorization")))
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+testUserToken)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusOK,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "Bearer "+testDelegatedToken, string(body))
			},
		},
		{
			name: "MissingBearerToken",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
				require.NoError(t, err)
				// No Authorization header.
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusUnauthorized,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
				var errResp jsonError
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
				assert.Equal(t, "unauthorized", errResp.Error)
				assert.Contains(t, errResp.ErrorDescription, "missing or invalid Bearer token")
			},
		},
		{
			name: "SessionHeaderPassthrough",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte(r.Header.Get("Mcp-Session-Id")))
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+testUserToken)
				req.Header.Set("Mcp-Session-Id", "abc123")
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusOK,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "abc123", string(body))
			},
		},
		{
			name: "UpstreamError",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+testUserToken)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusInternalServerError,
			verify:     nil,
		},
		{
			name:     "Healthz",
			upstream: nil, // not needed for healthz
			exc:      func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxyURL+"/healthz", nil)
				require.NoError(t, err)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusOK,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
				var status map[string]string
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))
				assert.Equal(t, "ok", status["status"])
			},
		},
		{
			name: "ExchangeFailure",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
			},
			exc: func() TokenExchanger { return newFailingExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+testUserToken)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusUnauthorized,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				var errResp jsonError
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
				assert.Equal(t, "unauthorized", errResp.Error)
				assert.Contains(t, errResp.ErrorDescription, "token exchange failed")
			},
		},
		{
			name: "InvalidBearerPrefix",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusUnauthorized,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				var errResp jsonError
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
				assert.Equal(t, "unauthorized", errResp.Error)
			},
		},
		{
			name: "PathPreservation",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte(r.URL.Path))
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/v1/mcp/messages", nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+testUserToken)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusOK,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "/v1/mcp/messages", string(body))
			},
		},
		{
			name: "RequestBodyPassthrough",
			upstream: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "read error", http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(body)
				}))
			},
			exc: func() TokenExchanger { return newSuccessExchanger() },
			request: func(t *testing.T, proxyURL string) *http.Response {
				t.Helper()
				body := `{"jsonrpc":"2.0","method":"tools/list","id":1}`
				req, err := http.NewRequestWithContext(
					context.Background(), http.MethodPost, proxyURL+"/mcp",
					strings.NewReader(body),
				)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+testUserToken)
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				return resp
			},
			wantStatus: http.StatusOK,
			verify: func(t *testing.T, resp *http.Response) {
				t.Helper()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{"jsonrpc":"2.0","method":"tools/list","id":1}`, string(body))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			upstreamURL := "http://127.0.0.1:1" // dummy, won't be reached for some tests
			if tt.upstream != nil {
				srv := tt.upstream(t)
				t.Cleanup(srv.Close)
				upstreamURL = srv.URL
			}

			proxyURL := startProxy(t, upstreamURL, tt.exc())
			resp := tt.request(t, proxyURL)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)

			if tt.verify != nil {
				tt.verify(t, resp)
			}
		})
	}
}

func TestProxy_UpstreamUnreachable(t *testing.T) {
	t.Parallel()

	// Point to a listener that immediately closes connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	unreachableAddr := ln.Addr().String()
	require.NoError(t, ln.Close())

	proxyURL := startProxy(t, "http://"+unreachableAddr, newSuccessExchanger())

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, proxyURL+"/mcp", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testUserToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	var errResp jsonError
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	assert.Equal(t, "bad_gateway", errResp.Error)
}
