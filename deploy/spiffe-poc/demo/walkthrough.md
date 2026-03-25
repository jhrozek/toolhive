# SPIFFE PoC — Presenter Walkthrough

Live demo cheat-sheet. Each step has what to say, what to run, and what to expect.

**Cluster:** `kind-spiffe-poc` | **Trust domain:** `toolhive.dev` | **Prerequisites:** `kubectl`, `openssl`, `python3` on PATH

---

## Setup: Apply the manifests

Apply in four stages so cert issuance and operator reconciliation can settle between stages.

```bash
# Stage 1 — namespaces, service accounts, agent pods
kubectl --context kind-spiffe-poc apply \
  -f deploy/spiffe-poc/demo/manifests/01-namespaces.yaml \
  -f deploy/spiffe-poc/demo/manifests/02-agent-service-accounts.yaml \
  -f deploy/spiffe-poc/demo/manifests/03-agent-pods.yaml

# Stage 2 — TLS certificates for the MCP proxy listeners (cert-manager issues from SPIFFE CA)
kubectl --context kind-spiffe-poc apply \
  -f deploy/spiffe-poc/demo/manifests/04-mcp-tls-certs.yaml

# Stage 3 — MCPExternalAuthConfig (registration allow-list, TLS secret refs)
kubectl --context kind-spiffe-poc apply \
  -f deploy/spiffe-poc/demo/manifests/05-auth-config-fetch.yaml \
  -f deploy/spiffe-poc/demo/manifests/06-auth-config-cluster-tools.yaml

# Stage 4 — MCPServer CRDs (operator creates proxy pods and services)
kubectl --context kind-spiffe-poc apply \
  -f deploy/spiffe-poc/demo/manifests/07-mcpserver-fetch.yaml \
  -f deploy/spiffe-poc/demo/manifests/08-mcpserver-cluster-tools.yaml
```

Wait for everything to be ready before continuing:

```bash
kubectl --context kind-spiffe-poc wait pod devops-agent intern-agent -n agents \
  --for=condition=Ready --timeout=60s
kubectl --context kind-spiffe-poc get pods -n toolhive-system
```

---

## Step 1: Identity is automatic

**Say:** Three AI agent workloads are running. None of them were given a password, an API key, or a secret. Each received a cryptographic identity automatically when Kubernetes scheduled the pod — no human involved.

**Run:**

```bash
kubectl --context kind-spiffe-poc get pods -n agents
kubectl --context kind-spiffe-poc get pods -n untrusted
```

```bash
# Read each pod's SVID certificate and extract the SPIFFE URI SAN (openssl runs locally)
kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep URI

kubectl --context kind-spiffe-poc exec -n agents intern-agent -- \
  cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep URI

kubectl --context kind-spiffe-poc exec -n untrusted rogue-agent -- \
  cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep URI
```

**Expect:**

```
URI:spiffe://toolhive.dev/ns/agents/sa/devops-agent
URI:spiffe://toolhive.dev/ns/agents/sa/intern-agent
URI:spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent
```

**Say:** The SPIFFE ID encodes namespace and service account. The SPIFFE CSI driver issued these certificates automatically — no `kubectl create secret`, no cert signing request. When a pod is deleted the identity is revoked; when rescheduled a fresh SVID arrives.

---

## Step 2: MCP servers have embedded auth

**Say:** Two MCP servers are running. Each has an embedded auth server that validates SVID client certificates and issues short-lived JWTs. The authorization policy lives inside the MCPServer spec itself — no external IdP, no separate policy engine deployment.

**Run:**

```bash
kubectl --context kind-spiffe-poc get mcpserver -n toolhive-system
```

Show the registration allow-list on the fetch auth config:

```bash
kubectl --context kind-spiffe-poc get mcpexternalauthconfig spiffe-auth-fetch \
  -n toolhive-system \
  -o jsonpath='{.spec.embeddedAuthServer.spiffeClientPolicy}' && echo
```

Show the Cedar authorization policy embedded in the fetch MCPServer:

```bash
kubectl --context kind-spiffe-poc get mcpserver fetch -n toolhive-system \
  -o jsonpath='{.spec.authzConfig.inline.policies[*]}' && echo
```

**Expect:** The `spiffeClientPolicy` lists `namespace: agents` as the only allowed namespace. The Cedar policy grants `devops-*` full tool access, `intern-*` access to `fetch_url` only, and all `agents/*` principals the ability to list tools.

**Say:** The policy is a Kubernetes resource. Changing it is a `kubectl apply`. No restart required.

---

## Step 3: SPIFFE cert becomes a JWT (devops-agent)

**Say:** devops-agent presents its SVID as a mTLS client certificate to the fetch proxy. The embedded auth server validates the SPIFFE ID and returns a short-lived JWT. The certificate *became* an OAuth token. No password, no API key.

**Run:**

```bash
TOKEN=$(kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  curl -sk --max-time 10 \
  --cert /var/run/secrets/spiffe.io/tls.crt \
  --key  /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/devops-agent&resource=https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080" \
  https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080/oauth/token \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Decode the JWT payload:

```bash
echo "$TOKEN" | cut -d. -f2 | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip()
padded = raw + '=' * ((4 - len(raw) % 4) % 4)
d = json.loads(base64.urlsafe_b64decode(padded))
for k in ['sub', 'iss', 'aud', 'exp']: print(f'{k}: {d.get(k)}')"
```

**Expect:**

```
sub: spiffe://toolhive.dev/ns/agents/sa/devops-agent
iss: https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080
aud: ['https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080']
exp: <unix timestamp>
```

**Say:** The `sub` claim *is* the SPIFFE ID. Cedar policies evaluate `claim_sub` directly. No username database, no role mapping — the workload identity flows straight through from certificate to policy.

---

## Step 4: devops-agent — full access

**Say:** Cedar policy for the fetch server permits devops-agent to call any tool. The `like` pattern matches the SPIFFE ID in the `sub` claim.

**Run:**

```bash
kubectl --context kind-spiffe-poc get mcpserver fetch -n toolhive-system \
  -o jsonpath='{.spec.authzConfig.inline.policies[0]}' && echo
```

**Expect:**

```
// devops-agent: full access to all tools
permit(principal, action == Action::"call_tool", resource)
  when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/devops-*" };
```

**Say:** Any tool, any resource. devops-agent is a privileged workload with full access to both servers. The same pattern applies to cluster-tools — one Cedar rule, no per-tool configuration.

---

## Step 5: intern-agent — token granted, tool call denied

**Say:** intern-agent is in the `agents` namespace so the registration allow-list lets it in — it gets a token. But the Cedar policy for cluster-tools only permits `devops-*` to call tools. intern gets a JWT and still can't do anything with it.

Get intern's cluster-tools token:

```bash
INTERN_TOKEN=$(kubectl --context kind-spiffe-poc exec -n agents intern-agent -- \
  curl -sk --max-time 10 \
  --cert /var/run/secrets/spiffe.io/tls.crt \
  --key  /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/intern-agent&resource=https://mcp-cluster-tools-proxy.toolhive-system.svc.cluster.local:8080" \
  https://mcp-cluster-tools-proxy.toolhive-system.svc.cluster.local:8080/oauth/token \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "${INTERN_TOKEN:0:50}..."
```

Show what the cluster-tools Cedar policy says about `call_tool`:

```bash
kubectl --context kind-spiffe-poc get mcpserver cluster-tools -n toolhive-system \
  -o jsonpath='{.spec.authzConfig.inline.policies[*]}' && echo
```

**Expect:** Token is issued successfully. The Cedar policy has no `permit` for `intern-*` on `call_tool`. Cedar is deny-by-default — any unmatched action is rejected with 403.

**Say:** Same namespace, same auth mechanism, different outcome. Having a valid token is not the same as having permission. Cedar narrows the blast radius: even if an intern-agent pod is compromised, the attacker can't reach the cluster tools.

---

## Step 6: rogue-agent — stopped at the door

**Say:** rogue-agent is in the `untrusted` namespace. The registration policy only allows the `agents` namespace. rogue-agent never gets a JWT — it can't even reach the Cedar layer.

**Run:**

```bash
kubectl --context kind-spiffe-poc exec -n untrusted rogue-agent -- \
  curl -sk --max-time 10 \
  --cert /var/run/secrets/spiffe.io/tls.crt \
  --key  /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent&resource=https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080" \
  https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080/oauth/token
```

**Expect:**

```json
{"error":"unauthorized","error_description":"SPIFFE ID is not authorized to register as a client"}
```

**Say:** The SPIFFE ID carried the namespace. The policy checked the namespace. The untrusted workload was rejected before Cedar even ran. No token means no access — not even a 403, the request never gets that far.

---

## Step 7: (Optional) Live policy change

**Say:** Policies live in the MCPServer spec. Changing them is a Kubernetes resource update — no restart, no redeploy.

Grant intern-agent access to cluster-tools by adding a policy:

```bash
kubectl --context kind-spiffe-poc edit mcpserver cluster-tools -n toolhive-system
```

Add this entry under `spec.authzConfig.inline.policies`:

```yaml
        - |
          // intern-agent: promoted to cluster-tools access
          permit(
            principal,
            action == Action::"call_tool",
            resource
          )
          when {
            principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/intern-*"
          };
```

Save and re-run the intern-agent token request from Step 5. The next tool call will be permitted.

---

## Quick reference

| Principal    | Server        | Token issued | `call_tool`            |
|--------------|---------------|:------------:|------------------------|
| devops-agent | fetch         | yes          | ALLOW (all tools)      |
| devops-agent | cluster-tools | yes          | ALLOW (all tools)      |
| intern-agent | fetch         | yes          | ALLOW (`fetch_url` only) |
| intern-agent | cluster-tools | yes          | DENY (no permit rule)  |
| rogue-agent  | fetch         | NO           | DENY (rejected at registration) |
| rogue-agent  | cluster-tools | NO           | DENY (rejected at registration) |
