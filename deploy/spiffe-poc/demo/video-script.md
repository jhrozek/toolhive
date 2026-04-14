# SPIFFE PoC — Presenter Narration Notes

Companion to `run-demo.sh`. The script runs each act, then pauses
with `[Press Enter to continue]`. Narrate during the pause, then
advance.

**Cluster:** `kind-toolhive` | **Trust domain:** `toolhive.dev`

**Prerequisites:** `kubectl`, `jq`, `jwt` (jwt-cli), `openssl` on PATH.
Keycloak deployed (`./setup-keycloak.sh`) for Act 4.

```bash
./deploy/spiffe-poc/demo/run-demo.sh
```

---

## Act 1 — Identity is automatic

**What the audience sees:** Three agent pods, each with a SPIFFE ID
extracted from its X.509 certificate (URI SAN).

```
spiffe://toolhive.dev/ns/agents/sa/devops-agent
spiffe://toolhive.dev/ns/agents/sa/intern-agent
spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent
```

**What to say:**

> Three AI agent workloads. None of them were given credentials for MCP
> authentication. Each received a cryptographic identity automatically
> at startup — the cert-manager CSI driver issues an X.509-SVID when
> Kubernetes schedules the pod. The SPIFFE ID encodes namespace and
> service account. When a pod dies, the identity dies with it.
>
> In production, SPIRE replaces the CSI driver with stronger attestation —
> node identity verified against cloud instance metadata, workloads
> verified by container image digest. The certificates look identical;
> the attestation chain gets deeper.

---

## Act 2 — Authentication via workload identity

**What the audience sees:** Token requests from all three agents.
devops-agent and intern-agent get tokens (green badges); rogue-agent
is denied (red badge + raw JSON error). Decoded JWT showing
`sub = spiffe://toolhive.dev/ns/agents/sa/devops-agent`.

**What to say:**

> Each agent presents its X.509-SVID via mTLS to the MCP proxy. The
> embedded auth server validates the SPIFFE ID and issues a short-lived
> JWT — the certificate became an OAuth token.
>
> The registration policy is a namespace allow-list: only the `agents`
> namespace may obtain tokens. rogue-agent's SVID is valid — signed by
> the same CA — but its SPIFFE ID is in `untrusted`. Rejected before
> any token is issued. No 403, no Cedar — it never gets that far.
>
> Look at the JWT `sub` claim — it IS the SPIFFE ID. Cedar policies
> evaluate it directly. No username database, no role mapping.

---

## Act 3 — Policy controls access

**What the audience sees:** Cedar policies for both proxies (autonomous
only — delegation policies come in Act 4). Then an authorization matrix:

| Principal    | Server        | list_tools | call_tool        |
|--------------|---------------|------------|------------------|
| devops-agent | fetch         | ALLOW      | ALLOW            |
| intern-agent | fetch         | ALLOW      | **DENY**         |
| rogue-agent  | fetch         | DENY       | DENY (no token)  |
| devops-agent | cluster-tools | ALLOW      | ALLOW            |
| intern-agent | cluster-tools | ALLOW      | **DENY**         |
| rogue-agent  | cluster-tools | DENY       | DENY (no token)  |

**What to say:**

> Having a token is not the same as having permission. Cedar policies on
> each proxy determine what each agent can do.
>
> devops-agent has full access everywhere — it's a trusted, privileged
> workload. intern-agent can list tools on both servers but cannot call
> any autonomously. rogue-agent never got a token, so it can't even list.
>
> Three agents, three tiers: full access, list-only, total rejection.
> But notice intern-agent is stuck — it can see what tools exist but
> can't use them on its own. That's intentional. The next act shows
> how delegation unlocks access.

---

## Act 4 — Delegation: human + agent identity

**What the audience sees:**

1. Keycloak user tokens fetched (devops-user, intern-user)
2. Token exchange request parameters (RFC 8693)
3. Two delegated JWTs issued — one per user
4. Decoded composite JWT showing `sub`, `email`, `act.sub`
5. Cedar delegation policies
6. Delegation matrix showing permit/deny by delegator

| User (delegator) | Agent (actor) | list_tools | call_tool |
|------------------|---------------|------------|-----------|
| (autonomous)     | devops-agent  | ALLOW      | ALLOW     |
| (autonomous)     | intern-agent  | ALLOW      | **DENY**  |
| devops-user      | intern-agent  | ALLOW      | ALLOW     |
| intern-user      | intern-agent  | ALLOW      | **DENY**  |

**What to say:**

> So far every agent acted alone. But what if a human wants to delegate
> authority to an agent? RFC 8693 token exchange combines two identities
> into one token.
>
> The agent already has its SPIFFE JWT from Act 2. The human authenticates
> to Keycloak — a standard OIDC IdP. The agent sends both tokens to the
> auth server's token exchange endpoint: the user's ID token as the
> subject, its own JWT as the actor. The auth server issues a delegated
> JWT with a composite identity.
>
> Look at the claims. `sub` is the Keycloak user UUID. `email` is the
> human's email. And `act.sub` is the agent's SPIFFE ID — who is acting
> on behalf of the human. Both identities travel in one token.
>
> Now Cedar evaluates the composite. The policy checks `claim_email` and
> `claim_act.sub` together. devops-user@example.com has a permit rule —
> intern-agent can now call fetch tools on their behalf. intern-user has
> no such rule — same agent, same tool, denied.
>
> The key insight: the intern-agent couldn't do this autonomously. The
> human's identity is what unlocked access. And the audit trail shows
> exactly who delegated to whom.

---

## Act 5 — Sidecar proxy: wrapping an unmodified agent

**Prerequisites:** The sidecar test pod must be deployed:
```bash
./deploy/spiffe-poc/demo/build-agent-proxy.sh
kubectl apply -f deploy/spiffe-poc/demo/manifests/10-sidecar-agent-pod.yaml
```

**What the audience sees:** Five pieces of evidence from actual logs:

1. Agent container has no SPIFFE creds (`ls` fails)
2. Sidecar bootstrap logs showing SPIFFE identity loaded
3. Sidecar debug logs showing token exchange with decoded claims
   (`sub`, `email`, `name`, `act.sub`)
4. Cedar context from MCP server showing composite identity evaluation
5. Cedar decision: allow (delegation policy matched)

**What to say:**

> Acts 1 through 4 used a custom agent that speaks SPIFFE natively.
> But real coding agents — Claude Code, Codex, Cursor — don't know
> about SPIFFE. They just send HTTP requests with a user token.
>
> So we built a sidecar proxy. Two containers in one pod: the agent
> and the proxy. The agent talks to localhost — plain HTTP, just a
> user token in the Authorization header. The sidecar intercepts
> every request, performs the token exchange transparently, and
> forwards to the MCP server over mTLS with the delegated JWT.
>
> The agent container has zero access to SPIFFE credentials. Look —
> the volume isn't even mounted. The security boundary is the
> container. The agent can't bypass the proxy because the MCP
> server requires mTLS, and only the sidecar has the certificate.
>
> Now look at the sidecar logs. It received the request, exchanged
> the user's Keycloak token for a delegated JWT — you can see the
> claims right here: sub is the Keycloak user UUID, email is
> devops-user@example.com, and act.sub is the sidecar's SPIFFE ID.
> Both identities in one token.
>
> And on the MCP server side, Cedar evaluated the same composite
> identity. Same policies as Act 4 — the difference is the agent
> didn't have to know anything about SPIFFE or token exchange. The
> sidecar handled it.
>
> This is the path to wrapping real coding agents. The agent thinks
> it's talking to a local MCP server. The sidecar makes it secure.

---

## Summary

**What the audience sees:** Five numbered points.

**What to say:**

> Five layers, one framework.
>
> Identity — SPIFFE SVIDs, provisioned automatically.
> Authentication — X.509 mTLS to OAuth JWT, no passwords.
> Authorization — Cedar policies, per-tool, per-workload.
> Delegation — RFC 8693 token exchange, composite identity.
> Sidecar proxy — unmodified agents wrapped transparently.
>
> Autonomous, delegated, or proxied — the same policy framework
> applies. Same audit trail. Least-privilege access for AI agents,
> enforced cryptographically. No service mesh required.

---

## Tips

- Pre-run once to warm up TLS handshakes and Keycloak port-forward.
- Deploy the sidecar test pod before running the script if you want Act 5.
  The script gracefully skips it if the pod isn't running.
- The JWT decode is the moment of insight in Act 2 — slow down there.
- The delegated JWT decode in Act 4 is the second moment — point out
  `sub` vs `act.sub`.
- Act 5's debug logs are the third moment — the sidecar shows what
  it exchanged, and the MCP server shows what Cedar evaluated. Two-sided
  proof that delegation happened.
- The three-beat escalation (devops succeeds / intern denied / rogue
  rejected) builds tension for the Act 4 payoff where intern gets
  unlocked via delegation. Act 5 extends the payoff: even agents
  that don't speak SPIFFE get the same protection.
- If time is short, the SPIRE callout in Act 1 can be trimmed to one
  sentence.
