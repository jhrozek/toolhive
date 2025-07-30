package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/logger"
)

func TestGetClaimsFromContext(t *testing.T) {
	t.Parallel()
	// Test with claims in context
	claims := jwt.MapClaims{
		"sub": "testuser",
		"iss": "test-issuer",
		"aud": "test-audience",
	}
	ctx := context.WithValue(context.Background(), ClaimsContextKey{}, claims)

	retrievedClaims, ok := GetClaimsFromContext(ctx)
	require.True(t, ok, "Expected to retrieve claims from context")
	assert.Equal(t, "testuser", retrievedClaims["sub"])
	assert.Equal(t, "test-issuer", retrievedClaims["iss"])

	// Test with no claims in context
	emptyCtx := context.Background()
	_, ok = GetClaimsFromContext(emptyCtx)
	assert.False(t, ok, "Expected no claims to be found in empty context")

	// Test with wrong type in context
	wrongCtx := context.WithValue(context.Background(), ClaimsContextKey{}, "not-claims")
	_, ok = GetClaimsFromContext(wrongCtx)
	assert.False(t, ok, "Expected no claims to be found when wrong type is in context")

	// Test with nil context - we intentionally pass nil to test the nil check
	//nolint:staticcheck // SA1012: Testing nil context handling is intentional
	_, ok = GetClaimsFromContext(nil)
	assert.False(t, ok, "Expected no claims to be found with nil context")
}

func TestGetClaimsFromContextWithDifferentClaimTypes(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		claims   jwt.MapClaims
		expected map[string]interface{}
	}{
		{
			name: "string_claims",
			claims: jwt.MapClaims{
				"sub":   "user123",
				"email": "user@example.com",
				"name":  "Test User",
			},
			expected: map[string]interface{}{
				"sub":   "user123",
				"email": "user@example.com",
				"name":  "Test User",
			},
		},
		{
			name: "mixed_claims",
			claims: jwt.MapClaims{
				"sub":   "user123",
				"exp":   int64(1234567890),
				"iat":   int64(1234567800),
				"admin": true,
			},
			expected: map[string]interface{}{
				"sub":   "user123",
				"exp":   int64(1234567890),
				"iat":   int64(1234567800),
				"admin": true,
			},
		},
		{
			name:     "empty_claims",
			claims:   jwt.MapClaims{},
			expected: map[string]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.WithValue(context.Background(), ClaimsContextKey{}, tc.claims)
			retrievedClaims, ok := GetClaimsFromContext(ctx)

			require.True(t, ok, "Expected to retrieve claims from context")

			for key, expectedValue := range tc.expected {
				assert.Equal(t, expectedValue, retrievedClaims[key], "Expected %s to be %v, got %v", key, expectedValue, retrievedClaims[key])
			}
		})
	}
}

func TestGetAuthenticationProvider(t *testing.T) {
	t.Parallel()
	// Initialize logger for testing
	logger.Initialize()

	ctx := context.Background()

	t.Run("nil_oidc_config_returns_local_provider", func(t *testing.T) {
		t.Parallel()
		provider, err := GetAuthenticationProvider(ctx, nil, false)
		require.NoError(t, err, "Expected no error when OIDC config is nil")
		require.NotNil(t, provider, "Expected provider to be returned")

		// Should return LocalAuthenticationProvider
		localProvider, ok := provider.(*LocalAuthenticationProvider)
		require.True(t, ok, "Expected LocalAuthenticationProvider when OIDC config is nil")
		require.NotNil(t, localProvider, "Expected non-nil LocalAuthenticationProvider")

		// Test that middleware is returned
		middleware := provider.Middleware()
		require.NotNil(t, middleware, "Expected middleware to be returned")

		// Test that discovery handler is nil for local auth
		discoveryHandler := provider.DiscoveryHandler()
		assert.Nil(t, discoveryHandler, "Expected nil discovery handler for local auth")
	})

	t.Run("nil_oidc_config_middleware_functionality", func(t *testing.T) {
		t.Parallel()
		provider, err := GetAuthenticationProvider(ctx, nil, false)
		require.NoError(t, err)

		// Test that the middleware works by creating a test handler
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r.Context())
			require.True(t, ok, "Expected claims to be present in context")
			assert.Equal(t, "toolhive-local", claims["iss"])
			w.WriteHeader(http.StatusOK)
		})

		// Wrap the test handler with the middleware
		wrappedHandler := provider.Middleware()(testHandler)

		// Create a test request
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// Execute the request
		wrappedHandler.ServeHTTP(w, req)

		// Check the response
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("valid_oidc_config_returns_jwt_provider", func(t *testing.T) {
		t.Parallel()
		// Mock OIDC configuration (minimal valid config)
		oidcConfig := &TokenValidatorConfig{
			Issuer:      "https://example.com/auth",
			JWKSURL:     "https://example.com/auth/.well-known/jwks.json",
			ClientID:    "test-client",
			ResourceURL: "https://api.example.com",
		}

		// JWT validator creation might succeed in some environments
		provider, err := GetAuthenticationProvider(ctx, oidcConfig, false)

		if err != nil {
			// Expected case: JWKS endpoint not reachable
			assert.Contains(t, err.Error(), "failed to create JWT validator", "Expected JWT validator creation error")
			assert.Nil(t, provider, "Expected nil provider when JWT validator creation fails")
		} else {
			// Unexpected success case: JWT validator was created
			require.NotNil(t, provider, "Expected provider when no error")
			jwtProvider, ok := provider.(*JWTAuthenticationProvider)
			require.True(t, ok, "Expected JWTAuthenticationProvider when OIDC config provided")
			require.NotNil(t, jwtProvider, "Expected non-nil JWTAuthenticationProvider")

			// Test provider methods work
			assert.NotNil(t, provider.Middleware(), "Expected middleware to be returned")
			assert.NotNil(t, provider.DiscoveryHandler(), "Expected discovery handler for JWT provider")
		}
	})

	t.Run("empty_oidc_config_causes_validation_error", func(t *testing.T) {
		t.Parallel()
		// Empty OIDC configuration should cause validation errors
		oidcConfig := &TokenValidatorConfig{}

		provider, err := GetAuthenticationProvider(ctx, oidcConfig, false)
		assert.Error(t, err, "Expected error with empty OIDC config")
		assert.Nil(t, provider, "Expected nil provider with invalid config")
	})

	t.Run("allowOpaqueTokens_parameter_passed_through", func(t *testing.T) {
		t.Parallel()
		// Test that allowOpaqueTokens parameter is passed through to JWT validator
		oidcConfig := &TokenValidatorConfig{
			Issuer:      "https://example.com/auth",
			JWKSURL:     "https://example.com/auth/.well-known/jwks.json",
			ClientID:    "test-client",
			ResourceURL: "https://api.example.com",
		}

		// Test with allowOpaqueTokens = true - we just verify the function doesn't panic
		provider, err := GetAuthenticationProvider(ctx, oidcConfig, true)

		if err != nil {
			// Expected case: JWKS endpoint not reachable
			assert.Nil(t, provider, "Expected nil provider when creation fails")
		} else {
			// Validation succeeded - verify provider type
			require.NotNil(t, provider, "Expected provider when no error")
			_, ok := provider.(*JWTAuthenticationProvider)
			assert.True(t, ok, "Expected JWTAuthenticationProvider")
		}
	})
}

func TestJWTAuthenticationProvider(t *testing.T) {
	t.Parallel()
	// Initialize logger for testing
	logger.Initialize()

	t.Run("middleware_method_returns_jwt_middleware", func(t *testing.T) {
		t.Parallel()
		// Create a mock JWT validator (we can't test the full flow without a real OIDC setup)
		mockValidator := &TokenValidator{
			issuer: "test-issuer",
		}

		provider := &JWTAuthenticationProvider{validator: mockValidator}

		middleware := provider.Middleware()
		require.NotNil(t, middleware, "Expected middleware to be returned")

		// Test that the middleware works with a simple request
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware(testHandler)
		require.NotNil(t, wrappedHandler, "Expected wrapped handler")
	})

	t.Run("discovery_handler_method_returns_auth_info_handler", func(t *testing.T) {
		t.Parallel()
		// Create a mock JWT validator
		mockValidator := &TokenValidator{
			issuer:      "test-issuer",
			jwksURL:     "https://example.com/.well-known/jwks.json",
			resourceURL: "https://api.example.com",
		}

		provider := &JWTAuthenticationProvider{validator: mockValidator}

		discoveryHandler := provider.DiscoveryHandler()
		require.NotNil(t, discoveryHandler, "Expected discovery handler to be returned")

		// We can test that it's an HTTP handler by making a simple request
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		// This should not panic and should return some response
		discoveryHandler.ServeHTTP(w, req)

		// We expect a JSON response (though it might be an error due to incomplete config)
		assert.NotEmpty(t, w.Body.String(), "Expected some response from discovery handler")
	})
}

func TestLocalAuthenticationProvider(t *testing.T) {
	t.Parallel()

	t.Run("middleware_method_returns_local_middleware", func(t *testing.T) {
		t.Parallel()
		mockMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})
		}

		provider := &LocalAuthenticationProvider{middleware: mockMiddleware}

		middleware := provider.Middleware()
		require.NotNil(t, middleware, "Expected middleware to be returned")

		// Test that the middleware works
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware(testHandler)
		require.NotNil(t, wrappedHandler, "Expected wrapped handler")

		// Execute a test request
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Expected middleware to work correctly")
	})

	t.Run("discovery_handler_method_returns_nil", func(t *testing.T) {
		t.Parallel()
		provider := &LocalAuthenticationProvider{middleware: nil}

		discoveryHandler := provider.DiscoveryHandler()
		assert.Nil(t, discoveryHandler, "Expected nil discovery handler for local auth")
	})
}

func TestAuthInfoHandler(t *testing.T) {
	t.Parallel()
	// Initialize logger for testing
	logger.Initialize()

	t.Run("valid_config_returns_rfc9728_compliant_response", func(t *testing.T) {
		t.Parallel()
		validator := &TokenValidator{
			issuer:      "https://auth.example.com",
			jwksURL:     "https://auth.example.com/.well-known/jwks.json",
			clientID:    "test-client",
			resourceURL: "https://api.example.com",
		}

		handler := validator.AuthInfoHandler()
		require.NotNil(t, handler, "Expected handler to be returned")

		// Create test request
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		// Execute request
		handler.ServeHTTP(w, req)

		// Check response status
		assert.Equal(t, http.StatusOK, w.Code, "Expected 200 OK response")

		// Check content type
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"), "Expected JSON content type")

		// Parse JSON response using the actual struct
		var response rfc9728AuthInfo
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Expected valid JSON response")

		// Verify RFC 9728 compliant fields
		assert.Equal(t, "https://api.example.com", response.Resource, "Expected correct resource URL")
		assert.Equal(t, []string{"https://auth.example.com"}, response.AuthorizationServers, "Expected correct authorization servers")
		assert.Equal(t, []string{"header"}, response.BearerMethodsSupported, "Expected header bearer method")
		assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", response.JWKSURI, "Expected correct JWKS URI")
		assert.Equal(t, []string{"mcp:read", "mcp:tools", "mcp:prompts"}, response.ScopesSupported, "Expected MCP scopes")
	})

	t.Run("cors_headers_set_correctly", func(t *testing.T) {
		t.Parallel()
		validator := &TokenValidator{
			issuer:      "https://auth.example.com",
			jwksURL:     "https://auth.example.com/.well-known/jwks.json",
			resourceURL: "https://api.example.com",
		}

		handler := validator.AuthInfoHandler()

		// Test with Origin header
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		req.Header.Set("Origin", "https://client.example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Check CORS headers
		assert.Equal(t, "https://client.example.com", w.Header().Get("Access-Control-Allow-Origin"), "Expected origin to be echoed")
		assert.Equal(t, "GET, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"), "Expected correct allowed methods")
		assert.Equal(t, "mcp-protocol-version, Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"), "Expected correct allowed headers")
		assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"), "Expected 24 hour max age")
	})

	t.Run("cors_headers_wildcard_when_no_origin", func(t *testing.T) {
		t.Parallel()
		validator := &TokenValidator{
			issuer:      "https://auth.example.com",
			jwksURL:     "https://auth.example.com/.well-known/jwks.json",
			resourceURL: "https://api.example.com",
		}

		handler := validator.AuthInfoHandler()

		// Test without Origin header
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Check wildcard CORS
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"), "Expected wildcard origin when no origin header")
	})

	t.Run("options_preflight_request_handled", func(t *testing.T) {
		t.Parallel()
		validator := &TokenValidator{
			issuer:      "https://auth.example.com",
			jwksURL:     "https://auth.example.com/.well-known/jwks.json",
			resourceURL: "https://api.example.com",
		}

		handler := validator.AuthInfoHandler()

		// Test OPTIONS preflight request
		req := httptest.NewRequest("OPTIONS", "/.well-known/oauth-protected-resource", nil)
		req.Header.Set("Origin", "https://client.example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Check preflight response
		assert.Equal(t, http.StatusNoContent, w.Code, "Expected 204 No Content for OPTIONS")
		assert.Equal(t, "https://client.example.com", w.Header().Get("Access-Control-Allow-Origin"), "Expected CORS origin")
		assert.Empty(t, w.Body.String(), "Expected empty body for OPTIONS response")
	})

	t.Run("missing_resource_url_returns_404", func(t *testing.T) {
		t.Parallel()
		validator := &TokenValidator{
			issuer:      "https://auth.example.com",
			jwksURL:     "https://auth.example.com/.well-known/jwks.json",
			resourceURL: "", // Empty resource URL
		}

		handler := validator.AuthInfoHandler()

		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Should return 404 when resource URL is not configured
		assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 Not Found when resource URL is not configured")
		assert.Contains(t, w.Body.String(), "OAuth discovery not available", "Expected error message about OAuth discovery")
	})

	t.Run("all_required_rfc9728_fields_present", func(t *testing.T) {
		t.Parallel()
		validator := &TokenValidator{
			issuer:      "https://auth.example.com",
			jwksURL:     "https://auth.example.com/.well-known/jwks.json",
			resourceURL: "https://api.example.com",
		}

		handler := validator.AuthInfoHandler()
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		var response rfc9728AuthInfo
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Verify all RFC 9728 required/recommended fields are present and valid
		assert.NotEmpty(t, response.Resource, "Expected resource field to have a value")
		assert.NotEmpty(t, response.AuthorizationServers, "Expected authorization_servers to have values")
		assert.NotEmpty(t, response.JWKSURI, "Expected jwks_uri to have a value")
		assert.NotEmpty(t, response.BearerMethodsSupported, "Expected bearer_methods_supported to have values")
		assert.NotEmpty(t, response.ScopesSupported, "Expected scopes_supported to have values")

		// Verify specific expected values
		assert.Contains(t, response.BearerMethodsSupported, "header", "Expected header bearer method")
		assert.Equal(t, "https://api.example.com", response.Resource, "Expected correct resource URL")
	})
}
