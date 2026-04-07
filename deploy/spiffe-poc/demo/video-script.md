# SPIFFE PoC -- Video Recording Script

Timed narration script for a ~2 minute terminal screen recording.
The presenter pastes commands from `video-commands.sh` while narrating.

**Setup:** Terminal at 120 columns, font size large enough for recording.

```bash
# Off-camera: bounce pods, copy helper scripts
deploy/spiffe-poc/demo/video-commands.sh --setup

# On-camera: start recording, then run
deploy/spiffe-poc/demo/video-commands.sh
```

The script runs each section's commands, then pauses with
`[Press Enter to continue]`. Narrate during the pause, then
press Enter to advance.

---

## [0:00-0:15] Opening -- Three agents, zero secrets

**What to say:**
> "Three agents. Two MCP servers. Zero secrets. Every pod got a
> cryptographic identity at startup -- automatically, using SPIFFE."

**What to type:**

```
kubectl --context kind-spiffe-poc get mcpserver -n toolhive-system
kubectl get mcpserver fetch -o jsonpath='{.spec.authzConfig.inline.policies}' | jq -r '.[]'
kubectl --context kind-spiffe-poc get pods -n agents
kubectl --context kind-spiffe-poc get pods -n untrusted
```

**What the audience sees:** Two MCPServer resources (`fetch` and
`cluster-tools`), then the Cedar policies showing:
- `devops-*` → full `call_tool` access
- `intern-*` → `call_tool` only on `fetch_url`
- `agents/*` → `list_tools`

Then three agent pods -- `devops-agent` and `intern-agent` in `agents`,
`rogue-agent` in `untrusted`. The audience now knows the rules before
seeing the enforcement.

---

## [0:10-0:30] Identity -- SPIFFE ID from the certificate

**What to say:**
> "Each pod's X.509 certificate carries a SPIFFE ID -- namespace and
> service account, baked in cryptographically. Today, cert-manager issues
> these using Kubernetes as the trust anchor. That gives us mTLS --
> credentials that can't be stolen from a log or an env var -- and a
> standardized identity format for cross-cluster federation."

**What to type:**

```
kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep URI
```

**What the audience sees:**

```
URI:spiffe://toolhive.dev/ns/agents/sa/devops-agent
```

**Say (over the output):**
> "But the architecture is designed for SPIRE. With SPIRE, you get deeper
> attestation -- node identity verified against cloud instance metadata,
> workloads verified by container image digest. SPIRE already has
> experimental Sigstore integration -- only pods running signed images
> from your CI pipeline get an identity. The application code doesn't
> change."

---

## [0:30-0:55] Authentication -- Certificate becomes a JWT

**What to say:**
> "The agent presents this certificate via mTLS to the MCP proxy. The
> embedded auth server validates the SPIFFE ID and issues a short-lived
> JWT. We extended the auth server with the IETF's
> draft-ietf-oauth-spiffe-client-auth -- the trust domain is modeled as
> another upstream identity source, alongside OIDC. Same auth server,
> two identity flows."

**What to type (get token + decode):**

```
TOKEN=$(kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/devops-agent&resource=https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080" \
  https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080/oauth/token \
  | jq -r .access_token)
jwt decode "$TOKEN"
```

**What the audience sees:** Color-coded JWT with header (ES256 algorithm)
and claims including:

```json
{
  "sub": "spiffe://toolhive.dev/ns/agents/sa/devops-agent",
  "aud": ["https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080"],
  "exp": 1774612671
}
```

**Say (over the output):**
> "The `sub` claim IS the SPIFFE ID. Cedar policies match on it
> directly. No username database, no role mapping. Under the hood, we
> generalized the auth server's upstream interface -- OIDC providers use
> a redirect flow, SPIFFE uses a direct assertion. The operator wires
> the TLS certificates and trust bundles into the proxy via CRD fields."

---

## [0:55-1:10] Tool call -- devops-agent calls a tool

**What to say:**
> "Now devops-agent calls a tool. The helper script handles the full
> MCP handshake -- mTLS authentication, session init, tool call.
> Running with `sh -x` so you can see each step."

**What to type** (mcp-call.sh pre-copied in preamble):

```
kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  sh -x /tmp/mcp-call.sh \
  https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080 \
  fetch '{"url":"https://httpbin.org/get","raw":true,"max_length":200}'
```

**What the audience sees:** Each step traced with `+`: the mTLS
token fetch, the MCP initialize, the tool call. Then the JSON-RPC
result with httpbin response data.

**Say (over the output):**
> "SPIFFE certificate to OAuth token to MCP tool call -- that's the
> full chain. No API keys, no secrets. The identity came from the
> infrastructure."

---

## [1:10-1:25] Cedar denial -- intern-agent blocked on cluster-tools

**What to say:**
> "Now intern-agent tries to call cluster-tools. Same namespace,
> valid certificate, gets a token -- but the Cedar policy on
> cluster-tools only permits devops. Intern can use fetch but
> not the cluster tools."

**What to type:**

```
kubectl --context kind-spiffe-poc exec -n agents intern-agent -- \
  sh /tmp/mcp-call.sh \
  https://mcp-cluster-tools-proxy.toolhive-system.svc.cluster.local:8080 \
  echo '{"message":"hello"}'
```

**What the audience sees:**

```json
{"Result":null,"Error":{"code":403,"message":"Unauthorized"},"ID":{}}
```

**Say (over the output):**
> "403. Token was issued, session was created, but Cedar said no.
> Two layers of defense: registration policy controls who gets in,
> Cedar controls what they can do per server. Same agent, different
> servers, different permissions."

---

## [1:25-1:40] Registration denial -- rogue-agent stopped at the door

**What to say:**
> "And the rogue agent. Same cluster, valid certificate -- but the
> SPIFFE ID is in the `untrusted` namespace. The registration policy
> rejects it before a token is ever issued."

**What to type:**

```
kubectl --context kind-spiffe-poc exec -n untrusted rogue-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent&resource=https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080" \
  https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080/oauth/token
```

**What the audience sees:**

```json
{"error":"unauthorized","error_description":"SPIFFE ID is not authorized to register as a client"}
```

**Say (over the output):**
> "No token, no access. Three agents, three outcomes: full access,
> tool-level restriction, total rejection. Identity is not the same
> as access."

---

## [1:40-1:55] Closing -- Where this is headed

**What to say:**
> "This is draft-ietf-oauth-spiffe-client-auth running on ToolHive.
> Next: RFC 8693 delegation -- when an agent acts on behalf of a user,
> both identities travel in one token with an `act` claim. And a real
> agent demo -- a pydantic-ai agent calling MCP tools, authenticated
> end-to-end via SPIFFE. Plus SPIRE integration for image provenance
> attestation via Sigstore. The IETF's agent auth draft recommends
> exactly this architecture."

**What to type:** Nothing. The script displays the summary table and
next steps automatically.

---

## Tips for recording

- Pre-run the commands once so responses are cached / warmed up.
  Cold cert validation can add a couple seconds.
- Paste commands rather than typing -- the video is about the output,
  not watching someone type.
- Pause briefly after each output appears so the audience can read it.
- If a command wraps in your terminal, widen the window or reduce font
  size. The token-fetch command is the longest; consider pre-pasting it.
- The JWT decode is the moment of insight -- slow down there.
- Total runtime ~2 minutes. Each segment is self-contained; if you
  need to cut for time, the Identity segment's SPIRE paragraph can be
  trimmed to one sentence.
- Copy `mcp-call.sh` into both agent pods during the preamble
  (off-camera) so on-camera you just run `kubectl exec ... sh -x`.
- The three-beat escalation (devops succeeds → intern denied by Cedar
  → rogue denied at registration) is the narrative arc. Don't rush it.
