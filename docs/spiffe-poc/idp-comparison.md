# IdP Comparison: Embedded AS vs Native IdP Agent Flows

This document compares ToolHive's embedded authorization server (implementing `draft-ietf-oauth-spiffe-client-auth` + RFC 8693) against native agent identity features in Entra, Okta, and Keycloak. It answers: "why build our own AS when IdPs already support agent identity?"

## Summary

| Capability | ToolHive AS | Entra Agent ID | Okta | Keycloak |
|-----------|-------------|---------------|------|----------|
| Agent identity in delegated token | `act.sub = spiffe://...` (RFC 8693) | `azp` + `xms_act_fct=11` (proprietary) | `cid` only (flat, no delegation) | `sub` only (no `act` claim) |
| Delegation semantics | RFC 8693 `act` claim (standards, nestable) | Proprietary `xms_*` facet claims | Not supported | Not supported |
| SPIFFE as direct auth credential | mTLS with X.509-SVID | WIF (public HTTPS JWKS required) | Static key registration only | External IdP token exchange |
| Per-workload identity granularity | SPIFFE URI (ns + SA + trust domain) | Per app registration | Per app registration | Per client |
| Standards portability | RFC 8693 + IETF draft (any OIDC consumer) | Entra-only claims | Okta-only | Keycloak-only |
| Cedar policy expression | `claim_act.sub like "spiffe://..."` | `claim_azp == "<app-id>"` | `claim_cid == "<app-id>"` | N/A |

---

## Microsoft Entra Agent ID

### What it is

Entra Agent ID (launched 2025-2026) is a dedicated agent identity sub-platform with new primitives:

- **Agent identity blueprint** — a service principal acting as a template/factory for agent identities
- **Agent identity** — a child SP per running agent (no credentials of its own, authenticates via blueprint)
- **Agent user** — a synthetic non-human user account for delegated permission flows

### How agent delegation works

Entra's Agent OBO flow is a proprietary extension of the standard OBO:

1. User authenticates → token `Tc` (audience = blueprint)
2. Blueprint authenticates with its own credential → token `T1`
3. Agent identity submits **both tokens** to Entra's OBO endpoint
4. Result: token with `oid=user`, `azp=agent_identity_app_id`, `xms_act_fct=11`

### Token claims

| Claim | Meaning |
|-------|---------|
| `oid` / `sub` | The human user (preserved through OBO) |
| `azp` | The agent identity's app ID |
| `xms_act_fct=11` | "The actor is an AgentIdentity" |
| `xms_sub_fct` | Subject facet (11=AgentIdentity, 13=AgentUser) |
| `xms_par_app_azp` | Blueprint app ID (parent of the agent identity) |

### Can SPIFFE feed into Entra Agent ID?

Yes, via Workload Identity Federation. The SPIFFE auth server's JWKS is registered as a trusted issuer on the blueprint's app registration. The agent's SPIFFE JWT serves as the blueprint's federated credential. Requirements:

- SPIFFE AS issuer must be **publicly reachable HTTPS** (Entra fetches JWKS at runtime)
- JWT signing must be **RS256**
- `sub` must exactly match the registered federated credential (case-sensitive)
- `aud` must be `api://AzureADTokenExchange`

### What Entra provides that ToolHive doesn't

- Conditional Access policies targeting agent identities (preview)
- Integration with Microsoft Graph and Azure resource RBAC
- Built-in audit logging in Entra sign-in logs
- Managed identity lifecycle (no custom credential rotation)

### What ToolHive provides that Entra doesn't

- **Standards-based delegation** — RFC 8693 `act` claim is portable across any OIDC consumer. Entra's `xms_*` claims are Entra-only.
- **SPIFFE identity granularity** — the SPIFFE URI encodes namespace, service account, and trust domain. Entra's `azp` is an app registration UUID — per-app, not per-pod.
- **Local policy evaluation** — Cedar evaluates at the MCP server with full access to SPIFFE-specific attributes. Entra's Conditional Access knows nothing about MCP tools or Cedar policies.
- **No public HTTPS requirement** — the embedded AS runs cluster-internal. Entra WIF requires internet-reachable JWKS.

### When to use Entra Agent ID instead

If your environment is Entra-only, per-app-registration granularity is sufficient for authorization, and you don't need Cedar policies that reference SPIFFE workload URIs, Entra Agent ID eliminates the embedded AS and provides a mature, managed identity platform with Conditional Access.

---

## Okta

### Agent identity support

Okta does **not** have an equivalent to Entra Agent ID. There is no dedicated agent identity primitive.

### Token exchange (RFC 8693)

Okta implements RFC 8693 for specific flows (Native SSO, device-to-web), but:

- **No `act` claim** is produced in any documented flow
- `actor_token` is used for device secrets, not delegation
- The exchanged token carries `cid` (service app UUID) and `sub` (user), but no structured delegation

### SPIFFE federation

- **No native mTLS/SVID support** — must extract the SPIFFE signing key and register it as a static JWKS on an Okta service app (`private_key_jwt`)
- **No workload identity lifecycle** — key rotation requires manual or scripted JWKS updates
- **OIDC IdP federation is browser-redirect only** — not usable for machine-to-machine flows

### What ToolHive provides that Okta doesn't

- RFC 8693 `act` claim (Okta doesn't produce it)
- SPIFFE X.509-SVID as direct authentication (Okta requires key extraction)
- Per-workload identity (Okta has per-app `cid` only)
- Cedar policy evaluation with SPIFFE attributes

### When to use Okta instead

Okta's token exchange can propagate user identity to downstream services (`sub` preserved, `cid` identifies the agent app). If your authorization only needs "which app is acting" (not "which specific workload instance"), and you don't need the `act` claim for audit trails, Okta-native flows avoid the embedded AS. However, the SPIFFE integration is significantly weaker than Entra's.

---

## Keycloak

### Agent identity support

Keycloak has no dedicated agent identity features, but its RFC 8693 token exchange and identity brokering provide flexible building blocks.

### Token exchange (RFC 8693)

Keycloak implements RFC 8693 natively with two relevant modes:

- **Internal-to-internal** — exchange a user token for one with a different audience (scope narrowing)
- **Internal-to-external** — retrieve stored upstream provider tokens (GitHub, Atlassian) for a brokered user session

Keycloak does **not** produce an `act` claim natively. The exchanged token carries the user's identity with the client's `azp`.

### SPIFFE federation

Keycloak supports external-to-internal token exchange: a SPIFFE JWT can be submitted with `subject_issuer=<spiffe-idp-alias>`, and Keycloak validates it against the registered external OIDC IdP. This bridges the workload identity into a Keycloak session.

### Upstream token brokering

Keycloak's strongest feature for this use case: when configured to store upstream provider tokens during brokered login, those tokens are retrievable via:

```
GET /realms/{realm}/broker/{provider_alias}/token
Authorization: Bearer <user's Keycloak token>
```

This means ToolHive (or the agent) can retrieve the user's GitHub/Atlassian/etc tokens from Keycloak without ToolHive needing to broker upstream access directly.

### What ToolHive provides that Keycloak doesn't

- RFC 8693 `act` claim (Keycloak doesn't produce it)
- SPIFFE X.509-SVID as direct mTLS authentication
- Cedar policy evaluation with workload identity attributes

### When to use Keycloak instead

Keycloak is the most flexible IdP for this use case. Its token exchange + identity brokering + upstream token storage provide the building blocks for agent flows without a custom AS. The main gap is the `act` claim and SPIFFE-specific Cedar policies.

---

## Upstream service access

When the agent needs tokens for upstream services (GitHub API, Azure resources, Jira):

| Flow | Mechanism | ToolHive's role |
|------|-----------|----------------|
| Delegated + MCP | RFC 8693 at ToolHive (existing) | Issues delegated token |
| Delegated + upstream | Agent keeps original IdP token | None |
| Autonomous + upstream (Entra) | SPIFFE JWT → Entra WIF → Entra token | None (JWKS trust only) |
| Autonomous + upstream (Okta) | SPIFFE key → Okta service app → Okta token | None (key registration) |
| Autonomous + upstream (Keycloak) | SPIFFE JWT → Keycloak external exchange | None (IdP config only) |
| Brokered upstream (Keycloak) | Keycloak stores GitHub/Atlassian tokens | None (Keycloak brokers) |
| Brokered upstream (Entra) | ToolHive does Entra OBO | Token broker |

---

## The bottom line

The embedded AS provides value precisely at the intersection of three capabilities no single IdP offers:

1. **SPIFFE workload identity as a first-class credential** (mTLS, not key extraction)
2. **RFC 8693 `act` claim** (standards-based delegation chain, portable)
3. **Cedar policy evaluation** (per-tool authorization using SPIFFE attributes)

For Entra-only shops that don't need these three in combination, Entra Agent ID is a serious production-grade alternative. For multi-IdP or Keycloak environments, the embedded AS fills gaps that no IdP covers. For Okta environments, the embedded AS is essential — Okta's agent identity support is the weakest of the three.
