# SPIFFE PoC: Implementation Deep Dive

This document walks through the code changes that implement SPIFFE workload identity for ToolHive's embedded authorization server. For the high-level overview, see the [one-pager README](README.md). For runtime behavior in the cluster, see [cluster-flows.md](cluster-flows.md).

The implementation spans 10 commits from `56a470dd5` through `8d052e270`, organized into six phases.

## Phase 1: Upstream generalization

**Files:** `pkg/authserver/upstream/oauth2.go`, `pkg/authserver/upstream/spiffe.go`, `pkg/authserver/upstream/doc.go`, `pkg/authserver/upstream/types.go`

### Problem

The `OAuth2Provider` interface assumed all upstream identity sources use browser redirect flows (authorization URL, code exchange, token refresh). SPIFFE has no redirect -- identity is asserted directly via the client certificate in the TLS handshake.

### Solution

Split the single interface into a hierarchy:

```
IdentityProvider (interface)
    |-- Type() ProviderType
    |
    +-- RedirectFlowProvider (interface)
    |       |-- AuthorizationURL()
    |       |-- ExchangeCodeForIdentity()
    |       +-- RefreshTokens()
    |
    +-- DirectAssertionProvider (interface)
            +-- ResolveIdentity(ctx) (*Identity, error)
```

`IdentityProvider` is the base interface with a single `Type()` method. `RedirectFlowProvider` covers OIDC and OAuth 2.0 (browser redirect ceremony). `DirectAssertionProvider` covers SPIFFE and any future direct assertion mechanism (e.g., cloud workload identity).

The old `OAuth2Provider` name is kept as a type alias (`OAuth2Provider = RedirectFlowProvider`) for backward compatibility.

### SPIFFEProvider

`SPIFFEProvider` (`pkg/authserver/upstream/spiffe.go`) implements `DirectAssertionProvider`. Its `ResolveIdentity` method reads the SPIFFE ID from the request context (placed there by the mTLS middleware, Phase 3) and returns an `Identity` with `Subject` set to the full SPIFFE ID string. No tokens are produced -- the X.509-SVID *is* the credential.

```go
func (p *SPIFFEProvider) ResolveIdentity(ctx context.Context) (*Identity, error) {
    spiffeID, ok := spiffe.SPIFFEIDFromContext(ctx)
    if !ok {
        return nil, fmt.Errorf("no SPIFFE ID in context")
    }
    // Defense-in-depth trust domain check (middleware also validates)
    if spiffeID.TrustDomain() != p.trustDomain {
        return nil, fmt.Errorf("trust domain mismatch: ...")
    }
    return &Identity{Subject: spiffeID.String()}, nil
}
```

A new `ProviderTypeSPIFFE` constant (`"spiffe"`) was added to `pkg/authserver/upstream/types.go` alongside the existing `"oidc"` and `"oauth2"` types.

## Phase 2: TLS transport

**Files:** `pkg/runner/config.go`, `pkg/runner/runner.go`

### Problem

The proxy listener was HTTP-only. mTLS requires TLS termination at the proxy.

### Solution

A new `TLSConfig` struct in `pkg/runner/config.go`:

```go
type TLSConfig struct {
    CertFile     string  // PEM certificate
    KeyFile      string  // PEM private key
    ClientCAFile string  // CA for client certificate verification (optional)
}
```

The `buildTLSConfig` function (`pkg/runner/runner.go:904`) constructs a `*tls.Config` with two important properties:

1. **Dynamic certificate reload** -- uses a `GetCertificate` callback that reloads from disk on each TLS handshake. This supports cert-manager rotation without proxy restart. (PoC trade-off: disk I/O per connection; production would cache with periodic refresh.)

2. **`tls.VerifyClientCertIfGiven`** -- accepts client certificates when presented but does not require them. This enables dual-mode operation: browser OIDC flows (no client cert) and SPIFFE mTLS flows (with client cert) on the same port. Application-layer auth (OIDC middleware, Cedar) still applies when no client cert is presented.

The CA pool for client verification is loaded once at startup. A proxy restart is required if the CA rotates -- noted as a PoC shortcut.

## Phase 3: SPIFFE middleware

**Files:** `pkg/authserver/spiffe/middleware.go`, `pkg/authserver/spiffe/context.go`

### Middleware chain position

The middleware wraps the auth server handler in `pkg/runner/runner.go:276`:

```go
if td := r.embeddedAuthServer.SPIFFETrustDomain(); !td.IsZero() {
    spiffeMW := authserverspiffe.NewMiddleware(td)
    handler = spiffeMW(handler)
}
```

It runs before all OAuth handlers (`/oauth/token`, `/oauth/authorize`, etc.).

### Extraction and validation

`NewMiddleware` returns a standard `func(http.Handler) http.Handler` that:

1. **No-ops when no client cert** -- if `r.TLS == nil` or `len(r.TLS.PeerCertificates) == 0`, the request passes through unchanged. This preserves browser OIDC flows.

2. **Filters for SPIFFE URIs** -- iterates `leaf.URIs`, selecting those with the `spiffe` scheme. Per the X.509-SVID spec (Section 2), exactly one `spiffe://` URI SAN is required. Non-SPIFFE URIs are ignored for compatibility with cert-manager which may add additional URIs.

3. **Validates the SPIFFE ID** -- parses with `go-spiffe/v2/spiffeid.FromURI()`, checks trust domain matches the expected one, and rejects paths containing `..` segments (defense-in-depth against directory traversal).

4. **Stores in context** -- `ContextWithSPIFFEID(ctx, id)` makes the parsed `spiffeid.ID` available to downstream handlers via `SPIFFEIDFromContext(ctx)`.

All failure paths return OAuth 2.0-formatted JSON error responses (`{"error": "invalid_client", "error_description": "..."}`) with HTTP 401.

## Phase 4: Client credentials grant

**Files:** `pkg/authserver/spiffe/client_auth.go`

### ClientAuthPreHandler

`ClientAuthPreHandler` wraps fosite's token endpoint handler. When a SPIFFE ID is present in the request context:

1. Reads `client_id` from the form body; if absent, uses the SPIFFE ID as the client_id.
2. Validates that `client_id` matches the SPIFFE ID from the certificate (per `draft-ietf-oauth-spiffe-client-auth`).
3. Checks the registration policy (Phase 5).
4. Auto-registers the client in fosite storage if not already registered.
5. Injects a dummy client secret so fosite's built-in authentication succeeds.

When no SPIFFE ID is in the context, the request passes through to the standard OAuth handler unchanged.

### The fosite workaround

Fosite requires a `client_secret` for confidential clients. Since real authentication already happened at the TLS layer, a per-process random secret (`internalClientSecret`, 32 random bytes hex-encoded) is generated at startup and injected into both `r.Form` and `r.PostForm`:

```go
var internalClientSecret = generateRandomSecret()

// In the handler:
r.Form.Set("client_secret", internalClientSecret)
r.PostForm.Set("client_secret", internalClientSecret)
```

**Why both Form and PostForm?** Fosite reads `r.PostForm` directly (see fosite `access_request_handler.go`), not `r.Form`. Setting only `r.Form` was one of the bugs caught during development.

The secret is randomized per process so it cannot be guessed by an attacker reaching the token endpoint without mTLS. Registered clients become invalid on restart (in-memory storage is cleared anyway). Production would implement a custom `fosite.ClientAuthenticationStrategy` that recognizes mTLS-authenticated clients and skips secret validation.

### Auto-registration

`ensureClientRegistered` handles TOCTOU races via check-then-register with `ErrAlreadyExists` fallback:

```go
_, err := stor.GetClient(ctx, clientID)
if err == nil { return nil }        // already registered
if !errors.Is(err, fosite.ErrNotFound) { return err }

// Register new client
client := registration.New(registration.Config{
    ID:         clientID,
    Secret:     internalClientSecret,
    Public:     false,  // confidential (mTLS-authenticated)
    GrantTypes: []string{"client_credentials"},
    Scopes:     scopesSupported,
    Audience:   allowedAudiences,
})
if err := stor.RegisterClient(ctx, client); err != nil {
    if errors.Is(err, storage.ErrAlreadyExists) {
        return nil  // concurrent registration, treat as success
    }
    return err
}
```

## Phase 5: Registration policy

**Files:** `pkg/authserver/spiffe/policy.go`

### ClientPolicy

Controls which SPIFFE IDs are allowed to auto-register:

```go
type ClientPolicy struct {
    AllowedIdentities []AllowedIdentity  // namespace/SA patterns
    MaxRegistrations  int                // 0 = unlimited
    registrationCount atomic.Int64       // thread-safe counter
}

type AllowedIdentity struct {
    Namespace      string  // exact match or "*"
    ServiceAccount string  // exact match or "*"
}
```

### Path parsing

`parseKubernetesPath` extracts namespace and service account from the standard Kubernetes SPIFFE ID path format `/ns/<namespace>/sa/<service-account>`. Returns false for non-conforming paths.

### MaxRegistrations

Uses an optimistic atomic increment: `registrationCount.Add(1)`, check against limit, roll back with `Add(-1)` if over. `DecrementRegistrations()` is also called on TOCTOU races (concurrent registration of the same client) and on registration failure, so that a slot consumed by a failed attempt is reclaimed.

The counter is defense-in-depth. With in-memory storage, a restart resets everything. Production with Redis storage would benefit more from this cap.

## Phase 6: Operator wiring

**Files:** `cmd/thv-operator/api/v1alpha1/mcpexternalauthconfig_types.go`, `cmd/thv-operator/pkg/controllerutil/authserver.go`

### CRD additions

Three new field groups on `EmbeddedAuthServerConfig`:

| Field | Type | Purpose |
|---|---|---|
| `spiffeTrustDomain` | string | Expected trust domain for SPIFFE client authentication |
| `spiffeClientPolicy` | `SPIFFEClientPolicyConfig` | AllowedIdentities + MaxRegistrations |
| `tls` | `ProxyTLSConfig` | Cert, key, and client CA secret references |

Cross-field validation ensures consistency:
- `spiffeTrustDomain` requires `tls` (mTLS needs a TLS listener)
- `spiffeClientPolicy` requires `spiffeTrustDomain`
- Upstream providers are optional when SPIFFE is configured (SPIFFE-only mode)

### Volume generation

`GenerateAuthServerVolumes` (`controllerutil/authserver.go`) creates volumes and mounts for the TLS certificate, key, and client CA:

| Volume | Mount path | Source |
|---|---|---|
| `proxy-tls-cert` | `/etc/toolhive/proxy-tls/tls.crt` | `tls.certSecretRef` |
| `proxy-tls-key` | `/etc/toolhive/proxy-tls/tls.key` | `tls.keySecretRef` |
| `proxy-tls-client-ca` | `/etc/toolhive/proxy-tls/client-ca.crt` | `tls.clientCASecretRef` |

All volumes use mode `0400` (read-only for owner).

### RunConfig building

`buildEmbeddedAuthServerRunnerConfig` maps CRD fields to `authserver.RunConfig`:
- `SPIFFETrustDomain` -> `config.SPIFFETrustDomain`
- `SPIFFEClientPolicy` -> `config.SPIFFEClientPolicy` (with `AllowedIdentities` mapped to `AllowedIdentityRunConfig`)

`AddEmbeddedAuthServerConfigOptions` also adds `runner.WithTLSConfig()` when `tls` is set, linking the TLS volume mount paths to the runner's `TLSConfig`.

## Bugs found and fixed

### Health probes fail under TLS

When the proxy serves HTTPS, Kubernetes HTTP health probes fail because they don't use TLS. The fix detects the `ProxyTLSCertVolumeName` in the pod's volume list and switches the probe scheme to `URISchemeHTTPS`.

### Audience enforcement gap

Inline OIDC configuration didn't default the `audience` field. When empty, JWT audience validation at the proxy's OIDC middleware rejected all tokens. Fix: default `audience = resourceUrl` when audience is unset in the inline OIDC resolver. The demo script also includes the `resource` parameter in token requests so the issued JWTs carry the correct `aud` claim matching the proxy's expected audience.

### PostForm vs Form

Fosite reads `r.PostForm` directly for client credentials, but the initial implementation only set `r.Form`. Fix: set both `r.Form` and `r.PostForm` for `client_id` and `client_secret`.

### Issuer URL mismatch

The issuer in `MCPExternalAuthConfig` didn't match the proxy's actual service URL. The OIDC discovery document advertised the wrong issuer, causing JWT validation to fail. Fixed to use the full `https://mcp-*-proxy.toolhive-system.svc.cluster.local:8080` form.

## Test coverage

| File | Type | What it tests |
|---|---|---|
| `middleware_test.go` | Unit | SPIFFE URI extraction, trust domain validation, path traversal, no-cert passthrough |
| `client_auth_test.go` | Unit | client_id matching, policy checking, auto-registration, dummy secret injection |
| `policy_test.go` | Unit | Namespace/SA pattern matching, wildcards, MaxRegistrations with concurrent access |
| `context_test.go` | Unit | Context round-trip (store and retrieve SPIFFE ID) |
| `upstream/spiffe_test.go` | Unit | SPIFFEProvider.ResolveIdentity, trust domain validation |
| `e2e_test.go` | E2E | Full mTLS handshake + client_credentials grant + JWT claim validation (skipped without certs) |
