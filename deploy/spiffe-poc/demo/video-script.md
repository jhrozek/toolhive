# SPIFFE PoC — Presenter Narration Notes

Companion to `run-demo.sh`. The script runs each act, then pauses
with `[Press Enter to continue]`. Narrate during the pause, then
advance.

**Cluster:** `kind-toolhive` | **Trust domain:** `toolhive.dev`

**Prerequisites:** `kubectl`, `jq`, `jwt` (jwt-cli), `openssl` on PATH.
Keycloak deployed (`./setup-keycloak.sh`) for Act 3.
Sidecar pod deployed (`./build-agent-proxy.sh` + manifests) for Act 4.

```bash
./deploy/spiffe-poc/demo/run-demo.sh
```

---

## Act 1 — Identity: how SPIFFE credentials are provisioned

**What the audience sees:** How the CSI driver provisions certificates,
the file layout on disk, and SPIFFE IDs from two agents (devops-agent
in `agents` namespace, rogue-agent in `untrusted`).

**What to say:**

> Every pod gets a cryptographic identity automatically. The cert-manager
> CSI driver requests a certificate from the SPIFFE CA when the pod is
> scheduled. The SPIFFE ID — trust domain, namespace, service account —
> is baked into the certificate as a URI SAN.
>
> The private key never leaves the pod. The cert rotates every hour.
> No human touched a key, no password was created, no secret was shared.
>
> Notice the SPIFFE IDs encode the namespace. devops-agent is in `agents`,
> rogue-agent is in `untrusted`. The identity carries the trust boundary.
>
> In production, SPIRE replaces the CSI driver with deeper attestation —
> node identity from cloud metadata, workload identity from image digest.
> The certificates look identical; the attestation gets stronger.

---

## Act 2 — Credential chain: from certificate to tool call

**What the audience sees:** devops-agent going through the full chain:
mTLS → JWT (with decoded claims), then rogue-agent rejected at
registration. Then the Cedar policy that governs tool access.

**What to say:**

> Follow one agent through the whole chain. devops-agent presents its
> X.509 certificate via mTLS to the MCP proxy's embedded auth server.
> The auth server checks the SPIFFE ID against a namespace allow-list
> and issues a short-lived JWT. This implements the IETF's
> draft-ietf-oauth-spiffe-client-auth.
>
> Look at the JWT claims: the `sub` claim IS the SPIFFE ID. The
> certificate became an OAuth token. Cedar policies match on `claim_sub`
> directly — no username database, no role mapping.
>
> Now rogue-agent tries the same thing. Its certificate is valid — signed
> by the same CA — but its SPIFFE ID is in the `untrusted` namespace.
> The registration policy rejects it. No JWT, no access.
>
> Same CA, same protocol. The difference is the namespace in the SPIFFE
> ID. Identity is not access.

---

## Act 3 — Delegation: human + agent identity

**What the audience sees:** Keycloak user tokens fetched, token exchange
performed, delegated JWT decoded showing composite identity (`sub`,
`email`, `act.sub`). Cedar delegation policy. Delegation matrix showing
intern-agent can call fetch only when delegated by devops-user.

**What to say:**

> So far agents acted alone. Now a human delegates authority. The user
> logs in to Keycloak — standard OIDC. The agent already has its SPIFFE
> JWT from Act 2. RFC 8693 token exchange combines them: user token as
> the subject, agent JWT as the actor, out comes a delegated JWT.
>
> Look at the claims. `sub` is the Keycloak user UUID. `email` is the
> human. `act.sub` is the agent's SPIFFE ID. Both identities in one
> token. The auth server minted this — not the agent, not the IdP.
>
> Cedar checks them together. The policy says: devops-user@example.com
> can call tools via any agent in the `agents` namespace. intern-user
> has no such rule.
>
> The matrix tells the story: intern-agent alone can't call fetch.
> But with devops-user's delegation, it can. Same agent, same tool —
> the human's identity is what unlocked access.

---

## Act 4 — Sidecar proxy: wrapping an unmodified agent

**Prerequisites:** Sidecar pod must be deployed:
```bash
./deploy/spiffe-poc/demo/build-agent-proxy.sh
kubectl apply -f deploy/spiffe-poc/demo/manifests/10-sidecar-agent-pod.yaml
```

**What the audience sees:** Five pieces of evidence:

1. Agent container has no SPIFFE creds (`ls` fails)
2. Sidecar bootstrap logs (SPIFFE identity loaded, agent JWT acquired)
3. Agent makes an MCP call to localhost with a user Bearer token
4. Sidecar debug logs showing token exchange with decoded claims
5. Cedar evaluation from the MCP server logs — what ToolHive received

**What to say:**

> Everything so far used agents that speak SPIFFE natively. But real
> coding agents — Claude Code, Codex, Cursor — don't know about
> SPIFFE. They just send HTTP requests.
>
> So we built a sidecar proxy. Two containers, one pod. The agent
> talks to localhost with a plain Bearer token. The sidecar handles
> everything: SPIFFE bootstrap, token exchange, mTLS forwarding.
>
> Look at the evidence. The agent container has no SPIFFE credentials —
> the volume isn't even mounted. The sidecar bootstrapped its own
> SPIFFE identity — coding-agent — and acquired an agent JWT.
>
> When the agent sends a request, the sidecar debug logs show the
> complete flow: received user token, performed token exchange,
> issued a delegated JWT with `sub=devops-user` and
> `act.sub=coding-agent`. Then forwarded to the MCP server.
>
> And on the MCP server side, you can see exactly what Cedar received —
> the same composite identity. Same policies as Act 3. The agent
> never touched a certificate or a private key.
>
> This is the path to wrapping real coding agents. The agent thinks
> it's talking to a local MCP server. The sidecar makes it secure.

---

## Summary

**What the audience sees:** Five-point summary + trade-offs section.

**What to say:**

> The credential chain: SPIFFE certificate, provisioned automatically.
> mTLS authentication, draft-ietf-oauth-spiffe-client-auth. Cedar
> authorization, per-tool. RFC 8693 delegation with composite identity.
> And a sidecar proxy that makes it all transparent to unmodified agents.
>
> One honest trade-off: the sidecar works today for agents that pass
> Bearer tokens. Agents like Claude Code that expect MCP auth discovery
> need the sidecar to run a local OAuth authorization server — that's
> our next step. But the architecture is proven: same policies,
> same audit trail, whether the agent is SPIFFE-native or wrapped.

---

## Tips

- Pre-run once to warm up TLS handshakes and Keycloak port-forward.
- Deploy the sidecar test pod before running if you want Act 4.
  The script gracefully skips it if the pod isn't running.
- Act 2's JWT decode is the first insight moment — slow down there.
- Act 3's delegated JWT decode is the second — point out `sub` vs `act.sub`.
- Act 4's debug logs are the third — the sidecar shows what it exchanged,
  the MCP server shows what Cedar evaluated. Two-sided proof.
- The narrative arc: identity → authentication → authorization → delegation
  → transparent wrapping. Each act builds on the previous.
- If time is short, Act 1's SPIRE callout and Act 4's trade-offs section
  can be trimmed.
