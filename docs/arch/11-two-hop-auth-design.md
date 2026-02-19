# Two-Hop Authentication: Preliminary Design

## Status

**Preliminary / RFC** -- This document describes the planned two-hop
authentication architecture. No implementation work has started.

## Problem Statement

Today, the ToolHive embedded auth server supports a single upstream Identity
Provider (IDP). The flow is:

```
MCP Client -> ToolHive Auth Server -> Company IDP (e.g. Okta)
```

This works when the MCP server only needs to know *who* the user is. However,
many MCP servers act as **proxies to third-party APIs** (GitHub, Slack, Jira,
cloud providers) that require their own OAuth tokens. The user must separately
authenticate with each external service, and ToolHive needs to broker that
second hop.

The desired flow is:

```
MCP Client -> ToolHive Auth Server -> Company IDP (authentication)
                                   -> External IDP (authorization for the MCP server's API)
```

We call this **two-hop auth** because the user is redirected through two
separate OAuth flows:

1. **Hop 1 (Company IDP):** Proves the user's corporate identity.
2. **Hop 2 (External IDP):** Obtains an access token for the external service
   the MCP server needs.

### Terminology

| Term | Meaning |
|------|---------|
| **Company IDP** | The organization's identity provider (Okta, Entra ID, etc.). Used for authentication. |
| **External IDP** | A third-party service (GitHub, Slack, Google, etc.) that the MCP server's tools call. Used for authorization. |
| **Hop 1** | The OAuth flow with the Company IDP. |
| **Hop 2** | The OAuth flow with the External IDP, initiated after Hop 1 completes. |
| **Primary identity** | The `ProviderIdentity` from the Company IDP. Always present. |
| **Linked identity** | A `ProviderIdentity` from an External IDP, linked to the same internal user via account linking. |
| **Consent record** | An auditable record that the user explicitly agreed to link an external provider. |

## Current Architecture (Single-Hop)

The current auth server architecture is described in detail in the codebase.
Key touchpoints for this design:

### Interfaces

- **`authserver.Server`** (`pkg/authserver/server.go`): Top-level interface
  with `Handler()`, `IDPTokenStorage()`, `Close()`.
- **`upstream.OAuth2Provider`** (`pkg/authserver/upstream/types.go`): Interface
  for upstream IDP communication (`AuthorizationURL`, `ExchangeCodeForIdentity`,
  `RefreshTokens`).
- **`storage.UserStorage`** (`pkg/authserver/storage/types.go`): User and
  provider identity management. Already supports multiple `ProviderIdentity`
  records per user.
- **`storage.UpstreamTokenStorage`** (`pkg/authserver/storage/types.go`):
  Session-keyed storage for upstream tokens. Used by the `upstreamswap`
  middleware to inject tokens into proxied requests.

### Authorize/Callback Flow

1. Client hits `/oauth/authorize` with PKCE
2. Auth server stores a `PendingAuthorization` keyed by internal state
3. Auth server redirects to the single upstream IDP
4. On `/oauth/callback`, exchanges code for identity, resolves/creates user,
   stores upstream tokens keyed by a session ID
5. Issues an authorization code to the client
6. Client exchanges code for a JWT containing a `tsid` claim (token session ID)
7. Proxy middleware uses `tsid` to look up stored upstream tokens and inject
   them into requests to the MCP server

### Current Constraints

- **Single upstream enforced**: `config.go` rejects `len(Upstreams) > 1`.
- **Single provider field**: Handler holds one `upstream.OAuth2Provider`.
- **`UpstreamTokenStorage` stores one set of tokens per session**: Keyed by
  session ID with a single `ProviderID`.

## Proposed Design

### High-Level Flow

```
                    MCP Client
                        |
                   (1) /oauth/authorize
                        |
                        v
               ToolHive Auth Server
                        |
                   (2) Redirect
                        |
                        v
                   Company IDP  <-- Hop 1
                        |
                   (3) /oauth/callback
                        |
                        v
               ToolHive Auth Server
                   [user authenticated]
                        |
              .---------+---------.
              |   Hop 2 needed?   |
              |                   |
             YES                  NO
              |                   |
     (4) /oauth/link/{provider}   |
              |                   |
              v                   |
        External IDP              |
              |                   |
     (5) /oauth/link/callback     |
              |                   |
              v                   |
        [consent + link]          |
              |                   |
              '---------+---------'
                        |
                (6) Issue auth code
                        |
                        v
                    MCP Client
                  [JWT with tsid]
```

### Design Principles

1. **Hop 1 is mandatory, Hop 2 is optional.** If no external IDP is configured,
   the flow is identical to today's single-hop.
2. **Explicit user consent.** The user must explicitly approve linking their
   external account. No silent account linking.
3. **Reuse existing abstractions.** The `OAuth2Provider` interface already
   supports both OIDC and OAuth2 providers. Hop 2 uses the same interface.
4. **Backward compatible.** Single-upstream configurations work exactly as
   before.
5. **Tokens are scoped per-provider.** The proxy middleware can select the
   correct upstream token based on which external service the MCP server needs.

### Component Changes

#### 1. Configuration: Multiple Upstreams

Lift the single-upstream restriction. Upstreams get a **role** annotation:

```yaml
upstreams:
  - name: company
    role: primary          # <-- NEW: Hop 1 (authentication)
    type: oidc
    oidc_config:
      issuer_url: https://company.okta.com
      client_id: toolhive-prod
      client_secret_file: /secrets/okta-secret
      scopes: [openid, profile, email, offline_access]

  - name: github
    role: linked           # <-- NEW: Hop 2 (authorization)
    type: oauth2
    oauth2_config:
      authorization_endpoint: https://github.com/login/oauth/authorize
      token_endpoint: https://github.com/login/oauth/access_token
      client_id: gh-app-id
      client_secret_file: /secrets/github-secret
      scopes: [repo, read:user]
      userinfo:
        endpoint_url: https://api.github.com/user
        additional_headers:
          Accept: application/vnd.github+json
        field_mapping:
          subject_fields: [id]
          name_fields: [login, name]
          email_fields: [email]
```

**New fields on `UpstreamRunConfig` / `UpstreamConfig`:**

| Field | Type | Description |
|-------|------|-------------|
| `role` | `UpstreamRole` | `"primary"` (company IDP) or `"linked"` (external IDP). Defaults to `"primary"` for backward compatibility. |

**Validation changes (`config.go`):**

- Remove `len(Upstreams) > 1` check.
- Enforce exactly one `role: primary` upstream.
- Allow zero or more `role: linked` upstreams.
- Enforce unique names (already done).

#### 2. Provider Registry

Replace the single `h.upstream` field with a registry of named providers:

```go
// ProviderRegistry holds initialized upstream providers indexed by name.
type ProviderRegistry struct {
    primary  upstream.OAuth2Provider       // Hop 1 (always exactly one)
    linked   map[string]upstream.OAuth2Provider  // Hop 2 providers by name
}

func (r *ProviderRegistry) Primary() upstream.OAuth2Provider { ... }
func (r *ProviderRegistry) Linked(name string) (upstream.OAuth2Provider, error) { ... }
func (r *ProviderRegistry) LinkedNames() []string { ... }
```

The existing `upstreamProviderFactory` creates each provider. No changes to the
factory or to `OAuth2Provider` implementations.

#### 3. Handlers

##### Modified: `/oauth/authorize`

No changes to the external interface. Internally, always redirects to the
**primary** provider (company IDP). The authorize handler continues to use
`registry.Primary()`.

##### Modified: `/oauth/callback`

After Hop 1 completes (company IDP callback):

1. Resolve/create the internal user (same as today).
2. Store the primary upstream tokens (same as today).
3. **Check if linked providers are configured.** If yes and the user has not yet
   linked the required external provider, redirect to the linking flow instead
   of issuing the auth code immediately.
4. If no linking needed, issue auth code (same as today).

The "check if linked" logic:

```
for each configured linked provider:
    look up ProviderIdentity(userID, providerName)
    if not found:
        redirect to /oauth/link/{providerName}?session=...
        return (do not issue auth code yet)
```

> **Open question:** Should linking be required (block until done) or optional
> (issue auth code, let the MCP server fail if the token is missing)? The
> initial design makes it **required when configured** -- if a linked provider
> is declared, the user must complete the linking before getting a token. This
> can be relaxed later with an `optional: true` flag on the upstream config.

##### New: `/oauth/link/{provider}`

Initiates Hop 2. This endpoint:

1. Validates the user has an active session (from Hop 1).
2. Looks up the linked provider by name from the registry.
3. Generates PKCE + state for the external IDP.
4. Stores a `PendingLinkAuthorization` (similar to `PendingAuthorization` but
   includes the internal user ID and the in-progress Hop 1 context).
5. Redirects to the external IDP's authorization endpoint.

##### New: `/oauth/link/callback`

Handles the external IDP callback:

1. Load `PendingLinkAuthorization` from state.
2. Exchange code for identity with the external IDP.
3. **Record explicit consent** (audit trail).
4. Create `ProviderIdentity` linking the external subject to the internal user.
5. Store the external upstream tokens under the same session ID (or a new one).
6. Resume the original authorization flow: issue the auth code to the client.

#### 4. Storage Extensions

##### `UserStorage` additions

Per the existing TODO in `storage/types.go`:

```go
type UserStorage interface {
    // ... existing methods ...

    // DeleteProviderIdentity unlinks a specific provider from a user.
    DeleteProviderIdentity(ctx context.Context, providerID, providerSubject string) error
}
```

Add a `Primary` field to `ProviderIdentity`:

```go
type ProviderIdentity struct {
    UserID          string
    ProviderID      string    // e.g., "company", "github"
    ProviderSubject string
    Primary         bool      // true for company IDP identity
    LinkedAt        time.Time
    LastUsedAt      time.Time
}
```

##### New: `ConsentStorage`

```go
type ConsentRecord struct {
    UserID     string    // Internal user who consented
    ProviderID string    // External provider being linked
    ConsentedAt time.Time
    // Future: scopes consented, expiration, revocation
}

type ConsentStorage interface {
    StoreConsent(ctx context.Context, record *ConsentRecord) error
    GetConsent(ctx context.Context, userID, providerID string) (*ConsentRecord, error)
    DeleteConsent(ctx context.Context, userID, providerID string) error
}
```

##### `UpstreamTokenStorage` changes

Currently stores one token set per session ID. For two-hop, a session needs
tokens from **both** the company IDP and the external IDP.

**Option A: Composite key (sessionID + providerID)**

```go
StoreUpstreamTokens(ctx, sessionID, providerID, tokens)
GetUpstreamTokens(ctx, sessionID, providerID) (*UpstreamTokens, error)
GetAllUpstreamTokens(ctx, sessionID) (map[string]*UpstreamTokens, error)
```

**Option B: Keep single key, store multiple tokens in the value**

```go
type SessionTokens struct {
    Tokens map[string]*UpstreamTokens  // providerID -> tokens
}
```

**Recommendation: Option A** -- it aligns with the existing interface shape and
avoids the need to deserialize the entire map for single-provider lookups.

#### 5. Upstream Swap Middleware

The `upstreamswap` middleware (`pkg/auth/upstreamswap/middleware.go`) currently
injects a single upstream token. With two-hop, it needs to know **which**
provider's token to inject.

**New config field:**

```go
type Config struct {
    HeaderStrategy  string `json:"header_strategy,omitempty"`
    CustomHeaderName string `json:"custom_header_name,omitempty"`
    ProviderID      string `json:"provider_id,omitempty"`  // NEW: which linked provider's token to inject
}
```

When `ProviderID` is set, the middleware calls
`GetUpstreamTokens(sessionID, providerID)` to get the external IDP's token
instead of the primary's.

When `ProviderID` is empty:
- If only one upstream exists (single-hop), behave as today.
- If multiple upstreams exist, default to the first `role: linked` provider's
  token (the most common case: inject the external service token, not the
  company IDP token).

#### 6. JWT Claims

No changes to the JWT structure. The `tsid` claim continues to reference the
session ID. The middleware uses `tsid` + `providerID` to look up the correct
token.

If needed in the future, a `linked_providers` claim could list which external
providers the user has linked, allowing MCP servers to make decisions without
a storage lookup. This is **out of scope** for the initial implementation.

### Sequence Diagram: Full Two-Hop Flow

```
MCP Client            ToolHive AS          Company IDP       GitHub (External)
    |                      |                    |                    |
    |  (1) /authorize      |                    |                    |
    |--------------------->|                    |                    |
    |                      |  (2) redirect      |                    |
    |                      |------------------->|                    |
    |                      |                    |                    |
    |                      |  (3) /callback     |                    |
    |                      |<-------------------|                    |
    |                      |                    |                    |
    |                      |  [resolve user,                        |
    |                      |   store company tokens,                |
    |                      |   check linked providers]              |
    |                      |                    |                    |
    |  (4) redirect to     |                    |                    |
    |  /oauth/link/github  |                    |                    |
    |<---------------------|                    |                    |
    |                      |                    |                    |
    |  (5) follow redirect |                    |                    |
    |--------------------->|                    |                    |
    |                      |  (6) redirect      |                    |
    |                      |---------------------------------------->|
    |                      |                    |                    |
    |                      |  (7) /link/callback|                    |
    |                      |<----------------------------------------|
    |                      |                    |                    |
    |                      |  [consent, link identity,              |
    |                      |   store github tokens]                 |
    |                      |                    |                    |
    |  (8) redirect with   |                    |                    |
    |  auth code           |                    |                    |
    |<---------------------|                    |                    |
    |                      |                    |                    |
    |  (9) POST /token     |                    |                    |
    |--------------------->|                    |                    |
    |  (10) JWT {tsid}     |                    |                    |
    |<---------------------|                    |                    |
    |                      |                    |                    |
    |  (11) MCP request    |                    |                    |
    |---[proxy]----------->|                    |                    |
    |                      |  [middleware: swap |                    |
    |                      |   tsid -> github   |                    |
    |                      |   access token]    |                    |
    |                      |------[to MCP server with GH token]---->|
```

### Error Handling

| Scenario | Behavior |
|----------|----------|
| User cancels Hop 1 (company IDP) | Standard OAuth error redirect to client. |
| User cancels Hop 2 (external IDP) | Redirect to client with `access_denied` error. The Hop 1 session is discarded. |
| External IDP returns error | Redirect to client with `server_error`. Log details. |
| User already linked (re-auth) | Skip the linking flow, proceed directly to auth code issuance. Optionally refresh the external tokens. |
| Linked provider token expired | The `upstreamswap` middleware passes the expired token through; the MCP server/backend rejects it. Future: trigger a refresh via the stored refresh token. |
| Consent revoked | `DeleteProviderIdentity` + `DeleteConsent`. Next auth flow will re-prompt for linking. |

### Security Considerations

1. **State binding across hops.** The `PendingLinkAuthorization` must be
   cryptographically bound to the Hop 1 session to prevent a confused deputy
   attack where an attacker initiates Hop 2 with a different user's Hop 1
   context.

2. **CSRF between hops.** Each hop uses independent state parameters. The
   internal state for Hop 2 is distinct from Hop 1's state. Both are
   cryptographically random and single-use.

3. **Token isolation.** External IDP tokens are stored separately from company
   IDP tokens. The `ProviderID` key prevents one provider's tokens from being
   accidentally returned for another.

4. **Consent is mandatory and auditable.** Account linking requires explicit
   consent. The consent record is persisted and can be audited.

5. **No automatic account linking by email.** Two identities are linked only
   through the authenticated OAuth flow, never by matching email addresses or
   other claims.

## Implementation Phases

### Phase 1: Foundation (Open-Source)

Prepare the open-source codebase for multi-upstream without implementing the
two-hop flow itself.

- Extend `UpstreamRunConfig` / `UpstreamConfig` with `Role` field.
- Add `ProviderRegistry` to replace single `h.upstream`.
- Add `Primary` field to `ProviderIdentity`.
- Add `DeleteProviderIdentity` to `UserStorage`.
- Add `ConsentRecord` type and `ConsentStorage` interface.
- Extend `UpstreamTokenStorage` to support composite keys
  (sessionID + providerID).
- Lift the `len(Upstreams) > 1` validation.
- Refactor handlers to use `ProviderRegistry.Primary()` (no behavior change).

### Phase 2: Two-Hop Implementation

- Implement `/oauth/link/{provider}` and `/oauth/link/callback` handlers.
- Implement the "check linked providers" logic in the callback handler.
- Add `PendingLinkAuthorization` storage.
- Update `upstreamswap` middleware with `ProviderID` support.
- Integration tests covering the full two-hop flow.

### Phase 3: Production Hardening

- Token refresh for linked provider tokens (background or on-demand).
- Consent management UI / API (list linked accounts, revoke).
- Multi-provider linking (link more than one external IDP per user).
- Optional vs. required linking configuration.
- Rate limiting on linking endpoints.

## Open Questions

1. **Should Hop 2 block auth code issuance or be lazy?** Current design says
   blocking. Alternative: issue the JWT immediately and let the MCP server
   trigger the linking flow via a well-known error response.

2. **How should token refresh work for linked providers?** Options: (a)
   middleware refreshes transparently using stored refresh token, (b) the MCP
   server returns a 401 and the client re-authorizes. Phase 1 does not address
   this.

3. **Should `PendingLinkAuthorization` reuse `PendingAuthorization` or be a
   separate type?** They share most fields but have different lifecycles. A
   separate type with shared embedded struct is likely cleanest.

4. **Multi-provider linking order.** If multiple linked providers are
   configured, should the user be prompted for all of them sequentially during
   the initial auth flow, or on-demand when the MCP server first needs a
   specific provider's token?

## References

- [MCP Specification: Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [RFC 6749: OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7591: Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 7636: PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- Existing TODO in `pkg/authserver/storage/types.go:228-232`
