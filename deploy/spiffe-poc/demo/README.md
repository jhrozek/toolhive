# SPIFFE PoC Demo Manifests

This directory contains the Kubernetes manifests for the SPIFFE PoC demo. They
demonstrate workload-identity-based MCP access control using SPIFFE SVIDs as
client certificates and Cedar policies for fine-grained authorization.

## Prerequisites

- `kind-spiffe-poc` cluster with Phase 0 infra applied (cert-manager,
  csi-driver-spiffe, `spiffe-ca-issuer` ClusterIssuer, `toolhive-system` namespace)
- toolhive-operator deployed to `toolhive-system`

## Manifests

| File | Contents |
|---|---|
| `01-namespaces.yaml` | `agents` and `untrusted` namespaces |
| `02-agent-service-accounts.yaml` | Service accounts for `devops-agent`, `intern-agent`, `rogue-agent` |
| `03-agent-pods.yaml` | curl pods with SPIFFE CSI volumes mounted at `/var/run/secrets/spiffe.io/` |
| `04-mcp-tls-certs.yaml` | cert-manager Certificates for `fetch` and `cluster-tools` MCP proxies |
| `06-auth-config.yaml` | MCPExternalAuthConfig resources wiring SPIFFE mTLS into the embedded auth server |
| `07-mcpserver-fetch.yaml` | MCPServer for gofetch with tiered Cedar policy |
| `08-mcpserver-cluster-tools.yaml` | MCPServer for yardstick with devops-only call_tool policy |

## Applying

```bash
CONTEXT=kind-spiffe-poc
kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/01-namespaces.yaml
kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/02-agent-service-accounts.yaml
kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/04-mcp-tls-certs.yaml

# Wait for certs to be issued
kubectl --context $CONTEXT wait certificate fetch-tls cluster-tools-tls \
  -n toolhive-system --for=condition=Ready --timeout=60s

kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/06-auth-config.yaml
kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/07-mcpserver-fetch.yaml
kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/08-mcpserver-cluster-tools.yaml
kubectl --context $CONTEXT apply -f deploy/spiffe-poc/demo/manifests/03-agent-pods.yaml

# Wait for agent pods
kubectl --context $CONTEXT wait pod devops-agent intern-agent \
  -n agents --for=condition=Ready --timeout=60s
kubectl --context $CONTEXT wait pod rogue-agent \
  -n untrusted --for=condition=Ready --timeout=60s
```

## SPIFFE Identity Mapping

| Pod | Namespace | Service Account | SPIFFE ID |
|---|---|---|---|
| `devops-agent` | `agents` | `devops-agent` | `spiffe://toolhive.dev/ns/agents/sa/devops-agent` |
| `intern-agent` | `agents` | `intern-agent` | `spiffe://toolhive.dev/ns/agents/sa/intern-agent` |
| `rogue-agent` | `untrusted` | `rogue-agent` | `spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent` |

## Authorization Matrix

| Principal | Server | list_tools | call_tool (fetch_url) | call_tool (other) |
|---|---|---|---|---|
| devops-agent | fetch | PERMIT | PERMIT | PERMIT |
| intern-agent | fetch | PERMIT | PERMIT | DENY |
| rogue-agent | fetch | DENY (blocked at registration) | DENY | DENY |
| devops-agent | cluster-tools | PERMIT | PERMIT | PERMIT |
| intern-agent | cluster-tools | PERMIT | DENY | DENY |
| rogue-agent | cluster-tools | DENY (blocked at registration) | DENY | DENY |

## How It Works

1. Agent pods receive a SPIFFE SVID via the CSI driver at startup.
2. When calling an MCP endpoint, the agent presents its SVID as a TLS client certificate.
3. The embedded auth server validates the SPIFFE ID against `spiffeClientPolicy`.
   - Identities from the `agents` namespace are allowed to register as OAuth clients.
   - `rogue-agent` (namespace `untrusted`) is rejected before it can obtain a token.
4. On successful registration, the auth server issues a short-lived JWT whose `sub`
   claim is set to the SPIFFE ID (e.g. `spiffe://toolhive.dev/ns/agents/sa/devops-agent`).
5. Cedar policies evaluate the `claim_sub` attribute from that JWT to permit or deny
   each `call_tool` / `list_tools` action.
