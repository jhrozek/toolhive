# SPIFFE PoC Documentation Outlines

Three documents, one audience each.

---

## Doc 1: One-Pager README (`docs/spiffe-poc/README.md`)

**Audience:** CEO, principal engineer, anyone needing the 2-minute version.

### Outline

1. **Title + one-sentence summary**
   - "SPIFFE Workload Identity for MCP Agents" -- zero-trust agent authentication without provisioned credentials.

2. **The problem** (3-4 sentences)
   - AI agents need credentials to call MCP servers.
   - Today: pre-provisioned client IDs and secrets per agent -- manual, fragile, doesn't scale.
   - Agents are ephemeral pods; credentials become stale, leaked, or forgotten.

3. **The solution** (3-4 sentences)
   - SPIFFE gives every pod a cryptographic identity (X.509-SVID) at startup.
   - The embedded auth server accepts that certificate as an OAuth client credential.
   - Cedar policies control which agent can call which tool -- per-tool, per-workload granularity.
   - No service mesh, no external IdP, no shared secrets.

4. **Architecture diagram** (ASCII art)
   - Show: agent pod -> SPIFFE SVID (CSI driver) -> mTLS -> MCP proxy (embedded AS) -> JWT -> Cedar -> MCP server
   - Three swim lanes: Identity Provisioning | Authentication | Authorization

5. **Demo results: authorization matrix**
   - 3x2 table: devops-agent, intern-agent, rogue-agent vs fetch, cluster-tools
   - Show ALLOW/DENY for list_tools and call_tool
   - One-line explanation per row

6. **Key design decisions** (bullet list)
   - VerifyClientCertIfGiven (coexists with browser OIDC)
   - SPIFFE ID -> JWT sub claim (Cedar evaluates claim_sub)
   - Registration policy: namespace/SA matching + max registrations cap
   - Dummy client secret (fosite workaround) -- production note

7. **What's next** (bullet list)
   - Token delegation (RFC 8693) for user-invoked agents
   - SPIRE integration for cross-cluster federation
   - Production hardening: cert caching, trust-manager, HSM-backed CA
   - Platform authorization CRDs (ToolhivePlatformRole etc.)

8. **Quick start** (3 commands)
   - `./deploy/spiffe-poc/setup.sh`
   - Deploy operator + apply demo manifests
   - `./deploy/spiffe-poc/demo/run-demo.sh`

---

## Doc 2: Implementation Deep Dive (`docs/spiffe-poc/implementation.md`)

**Audience:** Engineers who want to understand the code changes.

### Outline

1. **Introduction**
   - What was built, why, link to one-pager for context
   - Commit range: `1fdeb7e9a` through `8d052e270` (9 commits)

2. **Phase 1: Upstream generalization** (`pkg/authserver/upstream/`)
   - **Problem:** `OAuth2Provider` interface assumed browser redirect flows; SPIFFE has no redirect.
   - **Solution:** Split into `IdentityProvider` (base) -> `RedirectFlowProvider` + `DirectAssertionProvider`
   - Key files: `doc.go` (type hierarchy diagram), `types.go` (ProviderType), `spiffe.go` (SPIFFEProvider)
   - `SPIFFEProvider.ResolveIdentity()`: reads SPIFFE ID from context, returns Identity with Subject=SPIFFE ID
   - Backward compat: `OAuth2Provider` is a type alias for `RedirectFlowProvider`

3. **Phase 2: TLS transport** (`pkg/runner/runner.go`)
   - **Problem:** Proxy listener was HTTP-only; mTLS requires TLS.
   - `TLSConfig` struct: CertFile, KeyFile, ClientCAFile
   - `buildTLSConfig()`: GetCertificate callback reloads from disk (cert-manager rotation)
   - `tls.VerifyClientCertIfGiven` -- dual-mode: browser OIDC (no cert) + SPIFFE mTLS (cert)
   - CA pool loaded once at startup (PoC shortcut, noted for production)
   - Runner integration: `r.Config.TLSConfig` -> `transportConfig.TLSConfig`

4. **Phase 3: SPIFFE middleware** (`pkg/authserver/spiffe/middleware.go`)
   - Middleware chain position: runs before OAuth handlers
   - Extraction: `r.TLS.PeerCertificates[0].URIs` -> filter `spiffe://` scheme
   - Validation: exactly one SPIFFE URI SAN, trust domain match, no path traversal
   - No-op when no client cert (browser flow passthrough)
   - Context storage via `ContextWithSPIFFEID()` / `SPIFFEIDFromContext()`
   - OAuth-formatted JSON error responses for all failure paths

5. **Phase 4: Client credentials grant** (`pkg/authserver/spiffe/client_auth.go`)
   - `ClientAuthPreHandler`: wraps fosite's token endpoint
   - Flow: SPIFFE ID from context -> validate client_id matches -> check policy -> auto-register -> inject dummy secret
   - Fosite workaround: `internalClientSecret` (per-process random, 32 bytes hex)
   - Why: fosite requires client_secret for confidential clients; real auth happened at TLS layer
   - Auto-registration: `ensureClientRegistered()` with TOCTOU race handling via `ErrAlreadyExists`
   - Registered as confidential client with `grant_types: ["client_credentials"]`

6. **Phase 5: Registration policy** (`pkg/authserver/spiffe/policy.go`)
   - `ClientPolicy` struct: AllowedIdentities + MaxRegistrations + atomic counter
   - `AllowedIdentity`: Namespace + ServiceAccount, supports `*` wildcard
   - `parseKubernetesPath()`: extracts ns/sa from `/ns/<ns>/sa/<sa>` path
   - `IncrementRegistrations()`: optimistic atomic increment, rollback on overflow
   - `DecrementRegistrations()`: called on TOCTOU race or registration failure
   - Counter is defense-in-depth: in-memory storage means restart resets everything

7. **Phase 6: Operator wiring** (`cmd/thv-operator/`)
   - CRD fields added to `MCPExternalAuthConfig`:
     - `spiffeTrustDomain` (string)
     - `spiffeClientPolicy` (AllowedIdentities + MaxRegistrations)
     - `tls` (ProxyTLSConfig: cert, key, clientCA secret refs)
   - Cross-field validation: trust domain requires TLS, policy requires trust domain
   - Volume generation (`controllerutil/authserver.go`): cert, key, clientCA -> `/etc/toolhive/proxy-tls/`
   - RunConfig building: CRD -> `authserver.RunConfig` with SPIFFE fields
   - `AddEmbeddedAuthServerConfigOptions()`: also adds `runner.WithTLSConfig()`

8. **Bugs found and fixed**
   - **Health probes** (`mcpserver_controller.go`): HTTP probes fail when proxy serves HTTPS. Fix: detect `ProxyTLSCertVolumeName` in volumes -> set `probeScheme = URISchemeHTTPS`
   - **Audience enforcement** (`oidc/resolver.go`): inline OIDC config didn't default audience. Fix: `audience = resourceUrl` when audience is empty. Also required `resource` param on token requests.
   - **PostForm vs Form** (`client_auth.go`): fosite reads `r.PostForm` directly but initial code only set `r.Form`. Fix: set both `r.Form` and `r.PostForm` for client_id and client_secret.
   - **Issuer URL mismatch**: issuer in MCPExternalAuthConfig didn't match the actual service URL. Fixed to use full `https://mcp-*-proxy.toolhive-system.svc.cluster.local:8080` form.

9. **Test coverage**
   - Unit tests: middleware_test.go, client_auth_test.go, policy_test.go, context_test.go, spiffe_test.go (upstream)
   - E2E test: e2e_test.go -- full mTLS + client_credentials + token validation (skipped without certs)

---

## Doc 3: Cluster Flows Deep Dive (`docs/spiffe-poc/cluster-flows.md`)

**Audience:** Engineers who want to understand the runtime behavior in the cluster.

### Outline

1. **Introduction**
   - This doc follows a request through the cluster, not through the code.
   - Assumes familiarity with Kubernetes, cert-manager, SPIFFE concepts.
   - Reference: `deploy/spiffe-poc/` for infra, `deploy/spiffe-poc/demo/` for demo manifests.

2. **Infrastructure layer**
   - Components table: cert-manager v1.17.1, approver-policy v0.18.0, csi-driver-spiffe v0.9.1
   - CA chain: self-signed bootstrap -> spiffe-root-ca (ECDSA P-256) -> spiffe-ca-issuer (ClusterIssuer)
   - CertificateRequestPolicy: `allow-server-certs` approves requests via the CA issuer
   - Trust domain: `toolhive.dev`

3. **Flow 1: Identity provisioning** (cert-manager -> CSI driver -> pod)
   - Trigger: pod with `spiffe.csi.cert-manager.io` CSI volume is scheduled
   - CSI driver creates a CertificateRequest using the pod's ServiceAccount identity
   - approver-policy evaluates the request against CertificateRequestPolicy
   - cert-manager signs the CSR using spiffe-ca-issuer
   - CSI driver mounts `tls.crt`, `tls.key`, `ca.crt` at `/var/run/secrets/spiffe.io/`
   - SVID URI SAN: `spiffe://toolhive.dev/ns/<namespace>/sa/<service-account>`
   - Certificate duration: 1h (set in CSI volumeAttributes), auto-rotated by the driver

4. **Flow 2: Token acquisition** (mTLS -> embedded AS -> JWT)
   - **Step 1: TLS handshake**
     - Agent presents SVID as client cert; proxy presents its server cert (from cert-manager Certificate)
     - Both certs signed by the same CA (spiffe-ca-issuer) -- shared trust root
     - `VerifyClientCertIfGiven`: handshake succeeds even without a client cert
   - **Step 2: SPIFFE middleware extraction**
     - Parses `r.TLS.PeerCertificates[0].URIs`, filters for `spiffe://` scheme
     - Validates: exactly one SPIFFE URI, trust domain = `toolhive.dev`, no path traversal
     - Stores SPIFFE ID in request context
   - **Step 3: Client credentials grant**
     - Agent POSTs to `/oauth/token` with `grant_type=client_credentials&client_id=spiffe://...&resource=<proxy-url>`
     - `ClientAuthPreHandler` validates client_id matches SPIFFE ID from cert
     - Checks registration policy (namespace = `agents`, SA = `*`)
     - Auto-registers client in fosite storage if first-seen
     - Injects per-process dummy secret for fosite client_secret_post auth
   - **Step 4: JWT issuance**
     - fosite mints a client_credentials access token
     - JWT `sub` = SPIFFE ID, `iss` = proxy URL, `aud` = proxy URL (from resourceUrl)
   - **Actual curl command** (from demo script):
     ```
     curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
       --key /var/run/secrets/spiffe.io/tls.key \
       --cacert /var/run/secrets/spiffe.io/ca.crt \
       -X POST -H "Content-Type: application/x-www-form-urlencoded" \
       -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/devops-agent&resource=https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080" \
       https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080/oauth/token
     ```

5. **Flow 3: Token validation** (OIDC self-referencing -> JWKS)
   - Proxy's OIDC middleware validates the JWT it just issued
   - Self-referencing: issuer URL = proxy's own URL
   - JWKS endpoint: `<proxy-url>/.well-known/jwks.json` served by the same process
   - `jwksAllowPrivateIP: true` required because the proxy connects to itself on cluster-internal IP
   - `caBundleRef` on the MCPServer points to `spiffe-ca-bundle` ConfigMap (SPIFFE root CA)
   - Audience check: token `aud` must match `resourceUrl` on the MCPServer

6. **Flow 4: Authorization** (Cedar policy evaluation)
   - Cedar policy loaded from MCPServer `.spec.authzConfig.inline.policies`
   - Policy evaluates: `principal.claim_sub` (the SPIFFE ID from the JWT)
   - Pattern matching via Cedar `like` operator:
     - `"spiffe://toolhive.dev/ns/agents/sa/devops-*"` -- matches devops-agent
     - `"spiffe://toolhive.dev/ns/agents/sa/intern-*"` -- matches intern-agent
   - Actions: `Action::"call_tool"`, `Action::"list_tools"`
   - Resources: `Tool::"fetch_url"` (specific) or wildcard (any resource)

7. **The 3x2 authorization matrix** (with actual commands)
   - Table: devops-agent, intern-agent, rogue-agent x fetch, cluster-tools
   - For each cell: expected outcome, the actual curl command, and what happens
   - Format per cell:
     - Token request result (granted / denied with reason)
     - MCP call result (permitted / forbidden by Cedar)
   - **rogue-agent cells**: denied at registration policy ("SPIFFE ID is not authorized to register as a client")
   - **intern-agent + cluster-tools call_tool**: token granted, but Cedar has no matching permit -> implicit DENY

8. **Registration policy enforcement**
   - Policy config from MCPExternalAuthConfig:
     ```yaml
     spiffeClientPolicy:
       allowedIdentities:
         - namespace: agents
           serviceAccount: "*"
       maxRegistrations: 50
     ```
   - How namespace matching works: SPIFFE ID path `/ns/<ns>/sa/<sa>` parsed by `parseKubernetesPath()`
   - rogue-agent's SPIFFE ID: `spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent` -- namespace `untrusted` != `agents`
   - MaxRegistrations: atomic counter, optimistic increment with rollback
   - Defense-in-depth: even if policy is misconfigured, Cedar policies still apply

9. **PoC shortcuts and production considerations**
   - Broad RBAC for CertificateRequest creation (should be namespace-scoped)
   - Single CertificateRequestPolicy (split for server certs vs SVIDs)
   - Self-signed root CA (use HSM-backed CA for production)
   - Static CA bundle ConfigMap (use trust-manager for auto-rotation)
   - Per-handshake cert reload (cache with periodic refresh for production)
   - CA pool loaded once at startup (watch for rotation)
   - In-memory storage cleared on restart (use Redis for production)
   - Dummy client secret (implement custom fosite ClientAuthenticationStrategy)
