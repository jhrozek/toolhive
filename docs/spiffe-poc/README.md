# SPIFFE Workload Identity for MCP Agents

Zero-trust agent authentication and delegation for Kubernetes-native MCP workloads, without provisioned credentials.

## The problem

AI agents running as Kubernetes pods need credentials to call MCP servers. The current approach requires pre-provisioned client IDs and secrets per agent -- manual, fragile, and unscalable. Agents are ephemeral; their credentials become stale, leaked, or simply forgotten when pods are replaced.

When agents act on behalf of humans, there is no standard way to express *who delegated what to which agent*. Audit trails show "agent X called tool Y" but not "human Z told agent X to do it."

## The solution

SPIFFE gives every pod a cryptographic identity (an X.509-SVID) at startup, injected by cert-manager's CSI driver. ToolHive's embedded auth server accepts that certificate as an OAuth 2.0 client credential via mTLS (`draft-ietf-oauth-spiffe-client-auth`), auto-registering the workload and issuing a short-lived JWT. Cedar policies control per-tool, per-workload access.

For human delegation, RFC 8693 token exchange combines the user's OIDC identity (from Keycloak or any IdP) with the agent's SPIFFE JWT into a delegated token carrying both identities. Cedar evaluates the composite.

For unmodified agents (Claude Code, Codex), a sidecar proxy handles SPIFFE bootstrap, token exchange, and mTLS transparently.

## Architecture

```
                  ┌─────────────────────────────────────────────────┐
                  │  Credential Chain                               │
                  │                                                 │
  cert-manager    │  X.509-SVID ──► mTLS ──► client_credentials    │
  CSI driver      │                          ──► agent JWT          │
       │          │                                │                │
       ▼          │                                ▼                │
  ┌─────────┐     │  ┌───────────────────────────────────────┐      │
  │ Agent   │     │  │ MCP Proxy (embedded auth server)      │      │
  │ Pod     │─────│──│                                       │──────│──► MCP Server
  │         │     │  │ 1. Validate SVID (trust domain)       │      │    (fetch, etc.)
  │         │     │  │ 2. Check registration policy          │      │
  │ /var/   │     │  │ 3. Issue JWT (sub = SPIFFE ID)        │      │
  │ run/    │     │  │ 4. Cedar: authorize tool call         │      │
  │ secrets/│     │  └───────────────────────────────────────┘      │
  │ spiffe. │     │                                                 │
  │ io/     │     │  For delegation:                                │
  └─────────┘     │  user token (Keycloak) + agent JWT              │
                  │    ──► RFC 8693 exchange                        │
                  │    ──► delegated JWT (sub=user, act.sub=agent)  │
                  │    ──► Cedar: evaluate composite identity       │
                  └─────────────────────────────────────────────────┘

  Sidecar mode (unmodified agents):
  ┌──────────────┐    ┌─────────────────┐
  │ Agent        │    │ Sidecar proxy   │
  │ (unmodified) ├───►│ (SPIFFE creds)  │──mTLS──► MCP Proxy
  │ Bearer:      │    │ token exchange  │
  │ user_token   │    │ delegated JWT   │
  │ NO certs     │    │                 │
  └──────────────┘    └─────────────────┘
```

## Key components

| Component | Location | Role |
|-----------|----------|------|
| Upstream interface split | `pkg/authserver/upstream/` | `IdentityProvider` → `RedirectFlowProvider` (OIDC) + `DirectAssertionProvider` (SPIFFE) |
| SPIFFE middleware | `pkg/authserver/spiffe/` | Extracts SPIFFE ID from mTLS peer cert, stores in context |
| Client auth strategy | `pkg/authserver/spiffe/strategy.go` | Auto-registers SPIFFE clients, validates registration policy |
| Token exchange handler | `pkg/authserver/server/tokenexchange/` | RFC 8693: user token + agent JWT → delegated JWT with `act` claim |
| Multi-issuer validator | `pkg/authserver/server/tokenexchange/multi_issuer_validator.go` | Validates subject tokens from external issuers (Keycloak) via JWKS |
| oidc-trust upstream | `pkg/authserver/upstream/oidc_trust.go` | JWKS-only trust for Keycloak token validation (no redirect flow) |
| Agent proxy credential | `pkg/agentproxy/credential/` | SPIFFE mTLS client using go-spiffe/v2, file-watching cert rotation |
| Agent proxy exchanger | `pkg/agentproxy/exchanger/` | SPIFFE bootstrap + RFC 8693 delegation exchange with caching |
| Agent proxy reverse proxy | `pkg/agentproxy/proxy/` | localhost HTTP → upstream mTLS, Bearer token swap |
| Agent proxy binary | `cmd/thv-agent-proxy/` | Sidecar binary composing credential + exchanger + proxy |
| CRD upstream type | `cmd/thv-operator/api/v1alpha1/` | `UpstreamProviderTypeSPIFFE` in CRD enum with `SPIFFEUpstreamConfig` |

## Demo scenarios

### Autonomous agents (SPIFFE identity only)

| Agent | Namespace | Token issued | call_tool | Why |
|-------|-----------|:------------:|-----------|-----|
| devops-agent | agents | yes | ALLOW | Cedar: `claim_sub like "spiffe://...devops-*"` |
| intern-agent | agents | yes | DENY | No Cedar permit for intern on `call_tool` |
| rogue-agent | untrusted | NO | DENY | Registration policy rejects `untrusted` namespace |

### Delegation (human + agent)

| User (Keycloak) | Agent | call_tool | Why |
|-----------------|-------|-----------|-----|
| devops-user@example.com | intern-agent | ALLOW | Cedar: `claim_email == "devops-user@..."` + `claim_act.sub like "spiffe://...sa/*"` |
| intern-user@example.com | intern-agent | DENY | No Cedar permit for intern-user email |

### Sidecar proxy (unmodified agent)

| Evidence point | What it shows |
|----------------|---------------|
| Agent container `ls /var/run/secrets/spiffe.io/` | No SPIFFE creds (volume not mounted) |
| Sidecar bootstrap log | SPIFFE identity loaded, agent JWT acquired |
| Sidecar debug log | Token exchange: sub=user, act.sub=coding-agent |
| MCP server Cedar log | Same composite identity evaluated, decision logged |

## Key design decisions

- **`VerifyClientCertIfGiven`** — dual-mode TLS: mTLS for SPIFFE, plain TLS for browser OIDC, same listener.
- **SPIFFE ID = JWT `sub`** — Cedar policies evaluate `principal.claim_sub` directly. No mapping table.
- **oidc-trust upstream** — Keycloak provides JWKS trust for token exchange validation without participating in redirect flows. Separate CA from SPIFFE CA.
- **Top-level vs upstream SPIFFE config** — The CRD has both `spiffeTrustDomain` (top-level, controls mTLS middleware) and `spiffe` as an upstream provider type (per-upstream identity source). The demo currently uses the top-level fields; migration to upstream providers is a future step.
- **Sidecar uses `MTLSWebClientConfig`** — Server certs have DNS SANs (not SPIFFE URI SANs), so server verification uses standard web PKI while client auth uses SPIFFE SVIDs.
- **`singleflight` in exchanger** — Deduplicates concurrent bootstrap and exchange requests to prevent thundering herd.
- **Why an embedded AS instead of IdP federation?** — Entra Agent ID, Okta, and Keycloak each offer agent identity flows, but none produce RFC 8693 `act` claims or preserve SPIFFE URIs in delegated tokens. The embedded AS provides standards-based delegation with per-workload SPIFFE identity granularity that no single IdP offers. See [idp-comparison.md](idp-comparison.md) for the full analysis.

## Quick start

```bash
# 1. Create kind cluster with cert-manager + csi-driver-spiffe
./deploy/spiffe-poc/setup.sh

# 2. Deploy the ToolHive operator
task operator-deploy-local
kubectl apply -f deploy/charts/operator-crds/files/crds/

# 3. Apply demo manifests
kubectl apply -f deploy/spiffe-poc/demo/manifests/01-08*.yaml

# 4. Deploy Keycloak (for delegation)
./deploy/spiffe-poc/demo/setup-keycloak.sh

# 5. Build and deploy the sidecar proxy
./deploy/spiffe-poc/demo/build-agent-proxy.sh
kubectl apply -f deploy/spiffe-poc/demo/manifests/10-sidecar-agent-pod.yaml

# 6. Run the demo
./deploy/spiffe-poc/demo/run-demo.sh

# 7. Run the automated delegation test
./deploy/spiffe-poc/demo/run-delegation-demo.sh

# 8. Run the sidecar integration test
./deploy/spiffe-poc/demo/test-sidecar-delegation.sh
```

See `deploy/spiffe-poc/demo/README.md` for the detailed manifest apply sequence.
