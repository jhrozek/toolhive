# SPIFFE Workload Identity for MCP Agents

Zero-trust agent authentication for Kubernetes-native MCP workloads, without provisioned credentials.

## The problem

AI agents running as Kubernetes pods need credentials to call MCP servers. The current approach requires pre-provisioned client IDs and secrets per agent -- manual, fragile, and unscalable. Agents are ephemeral; their credentials become stale, leaked, or simply forgotten when pods are replaced.

## The solution

SPIFFE gives every pod a cryptographic identity (an X.509-SVID) at startup, injected by cert-manager's CSI driver. ToolHive's embedded authorization server accepts that certificate as an OAuth 2.0 client credential via mTLS, auto-registering the workload and issuing a short-lived JWT. Cedar policies then control which agent can call which tool -- per-tool, per-workload granularity. No service mesh, no external IdP, no shared secrets.

## How it works

```
                  Identity           Authentication              Authorization
                  Provisioning       (mTLS + OAuth)              (Cedar)
                  ============       ==============              =============

                  cert-manager
                  csi-driver-spiffe
                       |
                       v
  +-------------+   X.509-SVID    +------------------+  JWT   +----------+
  | Agent Pod   |---------------->| MCP Proxy        |------->| MCP      |
  |             |  TLS client     | (embedded AS)    | Bearer | Server   |
  | /var/run/   |  certificate    |                  | token  | (fetch,  |
  |  secrets/   |                 | 1. Validate SVID |        |  etc.)   |
  |  spiffe.io/ |                 | 2. Check policy  |        |          |
  |  tls.crt    |                 | 3. Register      |        |          |
  |  tls.key    |                 | 4. Issue JWT     |        |          |
  |  ca.crt     |                 | 5. Cedar eval    |        |          |
  +-------------+                 +------------------+        +----------+

  SPIFFE ID format: spiffe://toolhive.dev/ns/<namespace>/sa/<service-account>
  JWT sub claim:    spiffe://toolhive.dev/ns/agents/sa/devops-agent
  Cedar match:      principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/devops-*"
```

## Demo results: authorization matrix

Three agent pods, two MCP servers, zero provisioned secrets.

| Agent | MCP Server | list_tools | call_tool | Why |
|---|---|---|---|---|
| devops-agent | fetch | ALLOW | ALLOW (all tools) | Trusted namespace, broad Cedar permit |
| intern-agent | fetch | ALLOW | ALLOW (fetch_url only) | Trusted namespace, scoped Cedar permit |
| rogue-agent | fetch | DENY | DENY | Untrusted namespace -- blocked at registration |
| devops-agent | cluster-tools | ALLOW | ALLOW (all tools) | Trusted namespace, broad Cedar permit |
| intern-agent | cluster-tools | ALLOW | DENY | Trusted namespace, but no Cedar permit for call_tool |
| rogue-agent | cluster-tools | DENY | DENY | Untrusted namespace -- blocked at registration |

**rogue-agent** never receives a JWT. The registration policy rejects its SPIFFE ID (`ns/untrusted`) before it can obtain a token.

**intern-agent** gets a token for cluster-tools but Cedar has no matching `permit` rule for `call_tool` -- implicit deny.

## Key design decisions

- **VerifyClientCertIfGiven** -- the proxy accepts mTLS client certs but does not require them, so browser-based OIDC flows continue to work on the same listener.
- **SPIFFE ID becomes JWT `sub`** -- Cedar policies evaluate `principal.claim_sub`, matching on the SPIFFE ID directly. No mapping table needed.
- **Registration policy** -- namespace/service-account pattern matching (`AllowedIdentity`) plus a `MaxRegistrations` atomic counter as defense-in-depth.
- **Fosite workaround** -- fosite requires a client secret for confidential clients. Since real authentication happens at the TLS layer, a per-process random secret is injected into each request. Production would use a custom `ClientAuthenticationStrategy`.
- **Self-referencing OIDC** -- the proxy validates JWTs it issued by calling its own JWKS endpoint. Requires `jwksAllowPrivateIP: true` because the proxy connects to itself on a cluster-internal IP.

## What's next

- **Token delegation** (RFC 8693) for user-invoked agent flows: composite user+agent identity via `act` claim
- **SPIRE integration** for cross-cluster trust domain federation
- **Production hardening**: cert caching with periodic refresh, trust-manager for CA bundle rotation, HSM-backed CA
- **Platform authorization CRDs** (ToolhivePlatformRole, ToolhiveRoleBinding, ToolhiveAuthorizationPolicy)

## Quick start

```bash
# 1. Create kind cluster with cert-manager + csi-driver-spiffe
./deploy/spiffe-poc/setup.sh

# 2. Deploy the ToolHive operator to toolhive-system
#    (build and load the operator image into kind, then helm install)

# 3. Apply demo manifests (see deploy/spiffe-poc/demo/README.md for ordering)
kubectl --context kind-spiffe-poc apply -f deploy/spiffe-poc/demo/manifests/

# 4. Run the demo
./deploy/spiffe-poc/demo/run-demo.sh
```

See `deploy/spiffe-poc/demo/README.md` for the detailed manifest apply sequence (certs must be issued before MCPServer resources are applied).
