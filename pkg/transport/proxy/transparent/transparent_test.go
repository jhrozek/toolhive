package transparent

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/logger"
)

func init() {
	logger.Initialize() // ensure logging doesn't panic
}

func TestStreamingSessionIDDetection(t *testing.T) {
	t.Parallel()
	proxy := NewTransparentProxy("127.0.0.1", 0, "test", "http://example.com", nil, true, nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(200)

		// Simulate SSE lines
		w.Write([]byte("data: hello\n"))
		w.Write([]byte("data: sessionId=ABC123\n"))
		w.(http.Flusher).Flush()

		time.Sleep(10 * time.Millisecond)
		w.Write([]byte("data: more\n"))
	}))
	defer target.Close()

	// set up reverse proxy using ModifyResponse
	parsedURL, _ := http.NewRequest("GET", target.URL, nil)
	proxyURL := httputil.NewSingleHostReverseProxy(parsedURL.URL)
	proxyURL.FlushInterval = -1
	proxyURL.Transport = &tracingTransport{base: http.DefaultTransport, p: proxy}
	proxyURL.ModifyResponse = proxy.modifyForSessionID

	// hit the proxy
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", target.URL, nil)
	proxyURL.ServeHTTP(rec, req)

	// read all SSE lines
	sc := bufio.NewScanner(rec.Body)
	var bodyLines []string
	for sc.Scan() {
		bodyLines = append(bodyLines, sc.Text())
	}
	assert.Contains(t, bodyLines, "data: sessionId=ABC123")

	// side-effect: proxy should have seen session
	assert.True(t, proxy.IsServerInitialized, "server should have been initialized")
	_, ok := proxy.sessionManager.Get("ABC123")
	assert.True(t, ok, "sessionManager should have stored ABC123")
}

func createBasicProxy(p *TransparentProxy, targetURL *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = func(r *http.Request) {
		r.URL.Scheme = targetURL.Scheme
		r.URL.Host = targetURL.Host
		r.Host = targetURL.Host
	}
	proxy.FlushInterval = -1
	proxy.Transport = &tracingTransport{base: http.DefaultTransport, p: p}
	proxy.ModifyResponse = p.modifyForSessionID
	return proxy
}

func TestNoSessionIDInNonSSE(t *testing.T) {
	t.Parallel()

	p := NewTransparentProxy("127.0.0.1", 0, "test", "", nil, false, nil)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set both content-type and also optionally MCP header to test behavior
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"hello": "world"}`))
	}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)
	proxy := createBasicProxy(p, targetURL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", target.URL, nil)

	proxy.ServeHTTP(rec, req)

	assert.False(t, p.IsServerInitialized, "server should not be initialized for application/json")
	_, ok := p.sessionManager.Get("XYZ789")
	assert.False(t, ok, "no session should be added")
}

func TestHeaderBasedSessionInitialization(t *testing.T) {
	t.Parallel()

	p := NewTransparentProxy("127.0.0.1", 0, "test", "", nil, false, nil)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set both content-type and also optionally MCP header to test behavior
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "XYZ789")
		w.WriteHeader(200)
		w.Write([]byte(`{"hello": "world"}`))
	}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)
	proxy := createBasicProxy(p, targetURL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", target.URL, nil)
	proxy.ServeHTTP(rec, req)

	assert.True(t, p.IsServerInitialized, "server should not be initialized for application/json")
	_, ok := p.sessionManager.Get("XYZ789")
	assert.True(t, ok, "no session should be added")
}

func TestOAuthDiscoveryEndpoint(t *testing.T) {
	t.Parallel()
	logger.Initialize()

	ctx := context.Background()

	// Create a mock authentication provider with OAuth discovery
	oidcConfig := &auth.TokenValidatorConfig{
		Issuer:      "https://auth.example.com",
		JWKSURL:     "https://auth.example.com/.well-known/jwks.json",
		ClientID:    "test-client",
		ResourceURL: "https://api.example.com",
	}

	authProvider, err := auth.GetAuthenticationProvider(ctx, oidcConfig, false)
	if err != nil {
		// If JWT validator creation fails (expected in test environment), use local provider
		authProvider, err = auth.GetAuthenticationProvider(ctx, nil, false)
		require.NoError(t, err)
	}

	// Only test if we have a JWT provider with discovery handler
	if authProvider.DiscoveryHandler() == nil {
		t.Skip("No OAuth discovery handler available (using local auth)")
		return
	}

	// Create transparent proxy with authentication provider
	proxy := NewTransparentProxy("127.0.0.1", 0, "test", "http://example.com", nil, false, authProvider)

	// Start the proxy
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err = proxy.Start(ctx)
	require.NoError(t, err)
	defer proxy.Stop(ctx)

	// Test the .well-known/oauth-protected-resource endpoint
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	// Manually call the handler since we don't have the full server running
	if proxy.authProvider != nil && proxy.authProvider.DiscoveryHandler() != nil {
		proxy.authProvider.DiscoveryHandler().ServeHTTP(w, req)

		// Should return OAuth discovery information
		assert.Equal(t, http.StatusOK, w.Code, "Expected 200 OK for OAuth discovery")
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"), "Expected JSON content type")
		assert.Contains(t, w.Body.String(), "resource", "Expected resource field in response")
	}
}
