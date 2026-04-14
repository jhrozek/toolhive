# Future Directions

This document covers what needs to change to make the SPIFFE PoC compliant with `draft-ietf-oauth-spiffe-client-auth-01` and portable across SPIFFE implementations. For what was built, see [implementation.md](implementation.md). For runtime behavior, see [cluster-flows.md](cluster-flows.md).

---

## 1. Draft Compliance (draft-ietf-oauth-spiffe-client-auth-01)

### Compliance Matrix

| Requirement | Status | Notes |
|---|---|---|
| `client_id` = SPIFFE ID | YES | `client_auth.go:79-86` defaults `client_id` to SPIFFE ID, validates match |
| Trust domain validation | YES | Middleware validates at `middleware.go:92`, provider double-checks at `spiffe.go:46` |
| `client_credentials` grant | YES | Auto-registered clients use `client_credentials` only (`client_auth.go:178`) |
| Token `sub` = SPIFFE ID | YES | SPIFFE ID flows through as JWT subject via fosite session |
| SPIFFE ID path validation | YES | Path traversal defense-in-depth at `middleware.go:104` |
| RFC 8707 resource indicators | YES | `resource` parameter in token request sets JWT `aud` claim |
| RFC 6749 error responses | YES | All error paths return JSON `{"error": "...", "error_description": "..."}` |
| Registration policy | YES | Beyond spec: namespace/SA pattern matching + `MaxRegistrations` cap |
| Auth method name `"spiffe"` | PARTIAL | Currently advertises `tls_client_auth` instead of `spiffe` |
| Discovery metadata (SPIFFE fields) | PARTIAL | Missing `spiffe_trust_domains` and `spiffe_bundle_endpoint` |
| Trust bundle distribution | PARTIAL | Static file load; no dynamic bundle endpoint or Workload API |
| DCR with `"spiffe"` auth method | PARTIAL | Auto-registration works, but DCR endpoint doesn't accept `"spiffe"` method |
| Certificate-bound access tokens | NO | No `cnf` claim with `x5t#S256` thumbprint |
| JWT-SVID support | NO | Only X.509-SVID extraction; no JWT bearer assertion flow |
| SPIFFE bundle endpoint | NO | No HTTP endpoint serving the trust bundle |

### Partially Compliant Items

**Auth method name: `tls_client_auth` -> `spiffe`**

The draft defines a new token endpoint auth method named `"spiffe"`. The PoC uses `"tls_client_auth"` (RFC 8705) in two places:

- `pkg/oauth/constants.go:60` -- rename `TokenEndpointAuthMethodTLSClientAuth` to a new `TokenEndpointAuthMethodSPIFFE = "spiffe"` constant (keep the old constant for non-SPIFFE mTLS if needed)
- `pkg/authserver/server/handlers/discovery.go:119` -- advertise `"spiffe"` in `token_endpoint_auth_methods_supported`

The `"spiffe"` method implies mTLS with SPIFFE ID validation, which is stricter than generic `tls_client_auth`. Keeping `tls_client_auth` as a separate method for non-SPIFFE mTLS is valid.

**Discovery metadata: SPIFFE-specific fields**

The draft requires two additional metadata fields in the authorization server discovery document. The `AuthorizationServerMetadata` struct in `pkg/oauth/discovery.go:19` needs:

```go
// SPIFFETrustDomains lists the SPIFFE trust domains accepted by this AS.
// Per draft-ietf-oauth-spiffe-client-auth-01 Section 4.
SPIFFETrustDomains []string `json:"spiffe_trust_domains,omitempty"`

// SPIFFEBundleEndpoint is the URL where the SPIFFE trust bundle can be fetched.
// Per draft-ietf-oauth-spiffe-client-auth-01 Section 4.
SPIFFEBundleEndpoint string `json:"spiffe_bundle_endpoint,omitempty"`
```

`buildOAuthMetadata()` in `pkg/authserver/server/handlers/discovery.go:95` would populate these from the auth server config when a SPIFFE trust domain is configured.

**Trust bundle: static file load**

`buildTLSConfig` in `pkg/runner/runner.go:940` loads the client CA pool once at startup with `os.ReadFile`. The draft envisions dynamic trust bundle distribution. Two upgrade paths:

1. **SPIFFE Workload API** -- use `workloadapi.BundleSource` from `go-spiffe/v2` to watch for bundle updates. Requires a SPIRE agent or compatible workload API provider.
2. **SPIFFE bundle endpoint** -- periodic HTTP fetch from the federation endpoint (SPIFFE spec defines `https://<domain>/.well-known/spiffe-bundle`). Simpler, works without a local agent.

Either approach replaces the static `os.ReadFile` call with a source that updates the `tls.Config.ClientCAs` pool dynamically.

**DCR: `"spiffe"` auth method acceptance**

The auto-registration path in `client_auth.go:173` creates clients with `client_credentials` grant type but does not set a `token_endpoint_auth_method` on the registered client. When a formal DCR endpoint is exposed, it should accept `"spiffe"` as a valid `token_endpoint_auth_method` value and skip `client_secret` requirements for SPIFFE-authenticated registrations.

### Not Implemented

**Certificate-bound access tokens (RFC 8705 `cnf` claim)**

The draft recommends binding access tokens to the client's certificate via a `cnf` confirmation claim containing the certificate thumbprint (`x5t#S256`). This prevents token theft -- a stolen JWT is useless without the corresponding private key.

Implementation sketch:

1. In the SPIFFE client auth pre-handler (`pkg/authserver/spiffe/client_auth.go`), compute `sha256(leaf.Raw)` from `r.TLS.PeerCertificates[0]` and store it in the request context.
2. In session creation (`pkg/authserver/server/session/session.go:117`), add the thumbprint to the JWT claims Extra map:
   ```go
   claimsExtra["cnf"] = map[string]string{
       "x5t#S256": base64url(sha256(certDER)),
   }
   ```
3. Resource servers (the proxy's OIDC middleware) validate that the presenter's certificate thumbprint matches the `cnf.x5t#S256` claim. Requests without a matching cert are rejected even if the JWT signature is valid.

This is the highest-value compliance gap -- it closes the token-exfiltration attack vector.

**JWT-SVID support**

The current middleware (`pkg/authserver/spiffe/middleware.go`) only handles X.509-SVIDs extracted from TLS peer certificates. JWT-SVIDs are bearer tokens presented in an HTTP header, used in environments where mTLS termination happens upstream (cloud load balancers, service meshes).

Implementation sketch:

1. New middleware variant that reads `Authorization: Bearer <jwt-svid>` or a dedicated header.
2. Validate the JWT-SVID signature against the SPIFFE trust bundle's JWT signing keys.
3. Extract the SPIFFE ID from the JWT `sub` claim.
4. Store in context via the same `ContextWithSPIFFEID` function -- downstream code is unchanged.
5. The token request uses `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-svid` with the JWT-SVID as `client_assertion`.

The main complexity is disambiguating JWT-SVIDs from regular OIDC bearer tokens on the same endpoint. The `client_assertion_type` parameter handles this for the token endpoint; for other endpoints, a header convention or content inspection is needed.

**SPIFFE bundle endpoint**

The draft references a bundle endpoint where relying parties can fetch the trust bundle. This is a simple HTTPS endpoint serving the PEM-encoded CA certificates.

Implementation sketch:

1. New handler at `/.well-known/spiffe-bundle` that serves the contents of the client CA file.
2. Advertise the URL in discovery metadata as `spiffe_bundle_endpoint`.
3. Set appropriate `Cache-Control` headers (e.g., `max-age=3600`).
4. For federation across trust domains, the endpoint would serve a JSON document mapping trust domains to their bundles per the SPIFFE Trust Domain and Bundle specification.

---

## 2. Portability Across SPIFFE Implementations

The PoC was built on cert-manager's csi-driver-spiffe, but the architecture has a clean seam at `SPIFFEIDFromContext` (`pkg/authserver/spiffe/context.go:23`). Everything downstream of that function -- client auth, registration policy, session creation, Cedar evaluation -- is identity-source agnostic. Only the code that *populates* the context needs to change per implementation.

### Vault PKI

**Effort:** Trivial (zero code changes, infrastructure only)

Vault's PKI secrets engine can issue X.509 certificates with SPIFFE URI SANs. The certificates are structurally identical to what csi-driver-spiffe produces.

What changes:
- **Infrastructure:** Replace csi-driver-spiffe with Vault Agent sidecar or CSI provider injecting certs at the same mount path (`/var/run/secrets/spiffe.io/`).
- **CA bundle:** Point `clientCASecretRef` to Vault's CA certificate instead of cert-manager's.

What stays the same:
- All Go code. The middleware reads `r.TLS.PeerCertificates` regardless of who issued the cert.
- `buildTLSConfig` (`pkg/runner/runner.go:907`) loads certs from the same file paths.
- Registration policy, Cedar evaluation, JWT claims -- all unchanged.

### SPIRE

**Effort:** Small (~50-80 lines)

SPIRE is the reference SPIFFE implementation and the recommended production path. It provides stronger security than cert-manager through two-layer attestation: node attestation verifies the kubelet runs on a legitimate node (using cloud instance identity, TPM, etc.), then workload attestation verifies the process is what it claims to be (Kubernetes SA + pod UID + container image). Private keys are held in SPIRE Agent memory and never written to disk, unlike the CSI driver which writes `tls.key` as a file. SPIRE also natively supports trust bundle distribution and federation via the Workload API — eliminating the need for manual ConfigMap distribution.

The main code change is replacing file-based cert loading with the Workload API client.

What changes:
- **`pkg/runner/runner.go:907`** -- replace `buildTLSConfig`'s file-based `tls.LoadX509KeyPair` and `os.ReadFile` with `workloadapi.NewX509Source()`. This returns a `tls.Certificate` and trust bundle that auto-rotate without file I/O.
  ```go
  source, err := workloadapi.NewX509Source(ctx)
  // source.GetX509SVID() -> server cert
  // source.GetX509BundleForTrustDomain() -> CA pool
  ```
- **CSI volumes removed** -- no need for cert file mounts on agent pods. SPIRE Agent delivers SVIDs via a Unix domain socket.
- **`pkg/runner/config.go`** -- new config field for the Workload API socket path (default: `/tmp/spire-agent/public/api.sock`).

What stays the same:
- `pkg/authserver/spiffe/middleware.go` -- still reads `r.TLS.PeerCertificates`, unchanged.
- `pkg/authserver/spiffe/context.go` -- context storage, unchanged.
- `pkg/authserver/spiffe/client_auth.go` -- client auth flow, unchanged.
- `pkg/authserver/upstream/spiffe.go` -- provider, unchanged.

### Istio

**Effort:** Medium (~80-120 lines)

Istio terminates mTLS at the Envoy sidecar proxy. The application container receives plaintext HTTP with identity conveyed via the `X-Forwarded-Client-Cert` (XFCC) header.

What changes:
- **New middleware variant** -- parse the XFCC header instead of `r.TLS.PeerCertificates`. The header contains the client cert's URI SAN (the SPIFFE ID) and optionally the cert hash. Example:
  ```
  X-Forwarded-Client-Cert: By=spiffe://...;URI=spiffe://toolhive.dev/ns/agents/sa/devops-agent;Hash=abc123
  ```
- **`pkg/authserver/spiffe/middleware.go`** -- add an XFCC extraction path alongside the existing TLS extraction. A config flag selects which mode to use.
- **Trust model change** -- the proxy trusts the Envoy sidecar to perform certificate validation. The middleware validates the XFCC header format and SPIFFE ID structure but does not verify the certificate chain itself.
- **`pkg/runner/runner.go`** -- TLS termination is optional (Envoy handles it). `buildTLSConfig` may not be needed.

What stays the same:
- `pkg/authserver/spiffe/context.go` -- `ContextWithSPIFFEID` is unchanged; both middleware variants write to the same context key.
- `pkg/authserver/spiffe/client_auth.go` -- reads from context, unchanged.
- `pkg/authserver/upstream/spiffe.go` -- provider, unchanged.
- Cedar policies -- evaluate `principal.claim_sub` regardless of how the SPIFFE ID was obtained.

Security consideration: XFCC headers can be spoofed if the request doesn't pass through Envoy. The middleware must reject XFCC headers on direct connections (when `r.TLS` is present, prefer the TLS peer certificate over the header).

### JWT-SVIDs (AWS, cloud environments)

**Effort:** Large (~200+ lines)

Cloud environments often lack the ability to present X.509 client certificates (e.g., behind ALBs that terminate TLS). JWT-SVIDs carry SPIFFE identity as a signed JWT token.

What changes:
- **New middleware** -- validate JWT-SVID bearer tokens from an `Authorization` header or `client_assertion` parameter. Requires fetching the SPIFFE trust bundle's JWT signing keys.
- **`pkg/authserver/spiffe/middleware.go`** -- new JWT-SVID validation path. Parse the JWT, verify signature against the trust bundle's JWT authority keys, extract `sub` as the SPIFFE ID.
- **`pkg/authserver/spiffe/client_auth.go`** -- support `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-svid` on the token endpoint.
- **Disambiguation** -- the same `Authorization: Bearer` header carries both JWT-SVIDs (for authentication) and access tokens (for resource access). The token endpoint uses `client_assertion_type` to distinguish. Other endpoints need a convention (e.g., JWT-SVIDs only on `/oauth/token`, access tokens everywhere else).
- **Trust bundle management** -- need JWT authority keys in addition to X.509 CA certificates. May require a SPIFFE bundle endpoint client or Workload API integration.

What stays the same:
- `pkg/authserver/spiffe/context.go` -- `ContextWithSPIFFEID`, unchanged.
- `pkg/authserver/spiffe/policy.go` -- registration policy evaluates SPIFFE IDs regardless of credential type.
- `pkg/authserver/upstream/spiffe.go` -- provider, unchanged.
- Cedar policies -- unchanged.

---

## 3. Production Hardening

Items that are not draft-specific but required for production deployment.

**Replace per-process random secret with custom `fosite.ClientAuthenticationStrategy`**

The dummy secret approach (`pkg/authserver/spiffe/client_auth.go:34`) is documented as a PoC workaround. A custom strategy would:
- Recognize SPIFFE-authenticated requests (SPIFFE ID present in context).
- Skip `client_secret` validation entirely for those requests.
- Fall through to standard `client_secret_post` for non-SPIFFE clients.

This eliminates the secret injection into `r.Form`/`r.PostForm` and removes the `internalClientSecret` package variable.

**Dynamic CA bundle reload**

`buildTLSConfig` (`pkg/runner/runner.go:940`) loads the CA pool once. If the CA rotates (e.g., cert-manager root renewal), a proxy restart is required. Options:
- `fsnotify` watcher on the CA file with atomic swap of `tls.Config.ClientCAs`.
- Periodic reload (e.g., every 5 minutes) with comparison against the current pool.
- SPIFFE Workload API bundle source (if using SPIRE), which handles this automatically.

**TLS 1.3 enforcement**

`buildTLSConfig` sets `MinVersion: tls.VersionTLS12` (`pkg/runner/runner.go:921`). For SPIFFE workloads where all clients are modern, enforce TLS 1.3:
```go
MinVersion: tls.VersionTLS13,
```
This eliminates older cipher suites and simplifies the handshake.

**Rate limiting on token endpoint**

The token endpoint has no rate limiting. A compromised workload with a valid SVID could flood the endpoint. Rate limit per certificate thumbprint (SHA-256 of the leaf cert) on `/oauth/token`.

**Persistent registration store**

The in-memory fosite storage is cleared on restart. With Redis or database-backed storage:
- Registered clients survive proxy restarts.
- `MaxRegistrations` becomes a durable cap, not a per-process counter.
- Token revocation persists across restarts.

The storage interface (`pkg/authserver/storage`) already abstracts this -- a Redis implementation exists for the vMCP use case.

**Audit logging for SPIFFE authentication events**

Structured log events for:
- Successful SPIFFE client authentication (SPIFFE ID, cert serial, cert expiry).
- Registration policy denials (SPIFFE ID, matched/unmatched patterns).
- Auto-registration events (new client, concurrent registration race).
- `MaxRegistrations` limit reached.

Current logging uses `slog.Debug` and `slog.Warn`. Production should emit these at `slog.Info` level with consistent structured fields for log aggregation.

---

## 4. Completed (moved from future directions)

The following items were listed as future work and are now implemented:

- **SPIFFE upstream type in CRD enum** — `UpstreamProviderTypeSPIFFE` added with `SPIFFEUpstreamConfig` struct, webhook validation, and CRD-to-runtime converter. See Phase 8 in [implementation.md](implementation.md).
- **RFC 8693 user delegation with `act` claims** — Token exchange handler, multi-issuer validator, oidc-trust upstream, Keycloak integration. See Phase 7 in [implementation.md](implementation.md).
- **Real agent demo with pydantic-ai** — Python agent with SPIFFE mTLS, token exchange, and delegation. See `deploy/spiffe-poc/demo/agent/`.
- **Sidecar proxy for unmodified agents** — `thv-agent-proxy` binary with credential source, token exchanger, and reverse proxy. See Phase 9 in [implementation.md](implementation.md).

---

## 4. Manifest Migration: Top-Level to Upstream Provider

The demo manifests (`deploy/spiffe-poc/demo/manifests/05-auth-config-*.yaml`) still use the top-level `spiffeTrustDomain` and `spiffeClientPolicy` fields on `EmbeddedAuthServerConfig`:

```yaml
# Current (top-level fields)
spec:
  type: embeddedAuthServer
  embeddedAuthServer:
    spiffeTrustDomain: "toolhive.dev"
    spiffeClientPolicy:
      allowedIdentities:
        - namespace: agents
          serviceAccount: "*"
    upstreamProviders:
      - name: keycloak
        type: oidc-trust
```

Now that the CRD supports `spiffe` as an upstream provider type, the manifests could use:

```yaml
# Future (upstream provider pattern)
upstreamProviders:
  - name: spiffe-td
    type: spiffe
    spiffeConfig:
      trustDomain: "toolhive.dev"
  - name: keycloak
    type: oidc-trust
```

**Why this is not done yet:** The top-level `spiffeTrustDomain` controls two concerns: (1) the mTLS middleware (accept client certs from this trust domain) and (2) the SPIFFE upstream identity source. The CRD upstream `spiffe` type currently only maps to the latter. The mTLS middleware and `spiffeClientPolicy` (registration allow-list) are server-level concerns that remain top-level.

**Migration plan:** Either keep `spiffeClientPolicy` top-level (it's a server concern, not per-upstream) and move only `spiffeTrustDomain` to the upstream list, or model the entire SPIFFE configuration — trust domain + client policy — as an upstream with richer config.

---

## 5. Next Steps

### Tier 2 sidecar: local auth server for MCP-auth-aware agents

The current sidecar proxy (`thv-agent-proxy`) works for agents that pass Bearer tokens directly. Agents like Claude Code and Codex expect to perform MCP auth discovery (RFC 9728 Protected Resource Metadata) followed by an OAuth authorization code + PKCE flow. They don't just pass a pre-obtained token.

For these agents, the sidecar must run a **local MCP-compliant OAuth authorization server** on localhost:
1. The agent discovers auth requirements via `/.well-known/oauth-authorization-server`
2. The sidecar serves the OIDC login page (redirecting to the real IdP)
3. The user logs in via Keycloak/Entra/Okta
4. The sidecar receives the auth code callback, exchanges for tokens
5. The agent receives a local access token
6. On MCP calls, the sidecar exchanges the local token + SPIFFE JWT for a delegated token upstream

This is architecturally feasible — the sidecar would run a stripped-down instance of ToolHive's embedded auth server (`pkg/authserver/`). The machinery exists; it's a deployment topology change.

**Trade-offs:**
- Significant complexity increase (full OAuth AS in the sidecar)
- Session management between the agent, sidecar AS, and upstream MCP server
- Token refresh coordination
- Warrants a separate RFC in `toolhive-rfcs`

### Dynamic discovery metadata

`buildOAuthMetadata()` hardcodes `grant_types_supported`. When only SPIFFE is configured (no redirect flow providers), the discovery metadata should reflect this:
- `grant_types_supported`: only `["client_credentials"]`
- `token_endpoint_auth_methods_supported`: `["spiffe"]` only
- `authorization_endpoint`: omitted

### SPIRE integration

Replace cert-manager CSI driver with SPIRE for production-grade attestation:

- Two-layer attestation (node + workload) instead of trusting kubelet alone
- In-memory key storage (private keys never touch disk)
- Dynamic trust bundle distribution via Workload API
- Container-level identity differentiation (`k8s:container-name` selector)
- ~50-80 lines of code change in `pkg/runner/runner.go` (`workloadapi.NewX509Source`)

See Section 2 (Portability) for the detailed change analysis.

### MCPAgentProxy CRD

The operator could manage sidecar proxy pods via an `MCPAgentProxy` CRD:

```yaml
apiVersion: toolhive.stacklok.dev/v1alpha1
kind: MCPAgentProxy
metadata:
  name: coding-agent
spec:
  serviceAccountName: coding-agent
  agentContainer:
    image: my-coding-agent:latest
  mcpServers:
    - name: fetch
      ref: { name: fetch, namespace: toolhive-system }
```

The operator would auto-inject the sidecar container with SPIFFE CSI volume, assign listen ports, set agent env vars to `localhost:<port>`, and create NetworkPolicy. This follows the same pattern as the existing MCPServer controller (CRD → Deployment + Service) but for the client side.
