# SPIFFE PoC -- Video Recording Script

Timed narration script for a 60-90 second terminal screen recording.
The presenter pastes commands from `video-commands.sh` while narrating.

**Setup:** Terminal at 120 columns, font size large enough for recording.
Source the helper variables first (off-camera) by running the preamble
in `video-commands.sh`. This sets `CTX` and `FETCH` so the on-camera
commands stay short.

---

## [0:00-0:10] Opening -- Three agents, zero secrets

**What to say:**
> "What if every AI agent got a cryptographic identity automatically --
> no secrets, no API keys -- and policy controlled exactly which tools
> it could call? That's what we built. Three agent pods, two MCP
> servers, zero provisioned credentials."

**What to type:**

```
kubectl --context kind-spiffe-poc get pods -n agents
kubectl --context kind-spiffe-poc get pods -n untrusted
```

**What the audience sees:** Three running pods -- `devops-agent` and
`intern-agent` in the `agents` namespace, `rogue-agent` in `untrusted`.
All are Running. No secrets mounted, no env vars with API keys.

---

## [0:10-0:25] Identity -- SPIFFE ID from the certificate

**What to say:**
> "Each pod got an X.509 certificate at startup with a SPIFFE ID
> baked in. No human provisioned this -- cert-manager injected it when
> Kubernetes scheduled the pod."

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
> "The SPIFFE ID encodes namespace and service account.
> Delete the pod, reschedule it -- fresh identity in seconds."

---

## [0:25-0:45] Authentication -- Certificate becomes a JWT

**What to say:**
> "The agent presents this certificate via mTLS to the MCP proxy.
> The embedded auth server validates the SPIFFE ID and returns
> a short-lived JWT. The certificate became an OAuth token."

**What to type (get token):**

```
TOKEN=$(kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/devops-agent&resource=https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080" \
  https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080/oauth/token \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**What to type (decode JWT):**

```
echo "$TOKEN" | cut -d. -f2 | python3 -c "
import sys,base64,json
r=sys.stdin.read().strip(); r+='='*((4-len(r)%4)%4)
d=json.loads(base64.urlsafe_b64decode(r))
for k in['sub','aud','exp']:print(f'{k}: {d[k]}')"
```

**What the audience sees:**

```
sub: spiffe://toolhive.dev/ns/agents/sa/devops-agent
aud: ['https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080']
exp: 1743004800
```

**Say (over the output):**
> "The `sub` claim IS the SPIFFE ID. Cedar policies match on it
> directly. No username database, no role mapping."

---

## [0:45-0:55] Denial -- Rogue agent stopped at the door

**What to say:**
> "Now the rogue agent. Same cluster, valid certificate -- but it's in
> the `untrusted` namespace. The registration policy rejects it before
> a token is ever issued."

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
> "No token, no access. The SPIFFE ID carried the namespace, the policy
> checked it, done."

---

## [0:55-1:05] Closing -- Where this is headed

**What to say:**
> "This is draft-ietf-oauth-spiffe-client-auth running on ToolHive.
> Next: user delegation with `act` claims for composite agent+human
> identity, and a path to the IETF agent authentication standard."

**What to type:** Nothing. Let the denial output sit on screen while
delivering the closing line.

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
