# vMCP Upstream Authentication via Per-Resource WWW-Authenticate

## Status

Proposed

## Problem

When vMCP aggregates multiple backends that each require different upstream
OAuth providers (e.g., GitHub, Atlassian, Slack), clients need a way to
authenticate against the correct upstream for each backend. The challenge is
that:

1. A single vMCP instance fronts multiple backends with different auth
   requirements.
2. The MCP client has no knowledge of upstream providers — it only knows vMCP.
3. Standard OAuth discovery (RFC 9728) gives clients a single protected
   resource metadata document, which points to a single authorization server.
4. We need a mechanism to direct the client to the right upstream provider
   without requiring client-side extensions.

## Design

### Core Idea

Encode the upstream provider identity in the `resource_metadata` URL returned
in the `WWW-Authenticate` header of HTTP 401 responses. Each upstream gets its
own metadata path, and the client follows standard RFC 9728 discovery — no
custom behavior required.

### Flow

```
1. Client calls tool (e.g., github_create_issue)

2. vMCP routes request to GitHub backend
   vMCP detects: no upstream token for this user + upstream

3. vMCP returns HTTP 401 (not a JSON-RPC error) with:
   WWW-Authenticate: Bearer resource_metadata="https://vmcp.example.com/.well-known/oauth-protected-resource/upstream/github"

4. Client reads resource_metadata URL from the header (standard RFC 9728)

5. Client fetches that URL, receives:
   {
     "resource": "https://vmcp.example.com",
     "authorization_servers": [
       "https://authserver.example.com?upstream=github"
     ]
   }

6. Client initiates standard OAuth against that authorization server URL
   The ?upstream=github parameter rides along transparently

7. Authserver reads upstream=github, redirects to GitHub's OAuth flow

8. User authenticates at GitHub

9. Authserver receives callback, stores GitHub tokens, issues authorization code

10. Client exchanges code for token, retries tool call — succeeds
```

Every step uses standard protocols. The client has no awareness of upstream
selection — it is just following URLs.

### Sequence Diagram

```
┌────────┐         ┌──────┐         ┌───────────┐       ┌────────┐
│ Client │         │ vMCP │         │ AuthServer │       │ GitHub │
└───┬────┘         └──┬───┘         └─────┬─────┘       └───┬────┘
    │  tools/call      │                   │                  │
    │─────────────────>│                   │                  │
    │                  │ (no upstream      │                  │
    │                  │  token for user)  │                  │
    │  HTTP 401        │                   │                  │
    │  WWW-Authenticate: Bearer            │                  │
    │  resource_metadata="...upstream/github"                 │
    │<─────────────────│                   │                  │
    │                  │                   │                  │
    │  GET /.well-known/oauth-protected-resource/upstream/github
    │─────────────────>│                   │                  │
    │  { authorization_servers:            │                  │
    │    ["https://authserver?upstream=github"] }             │
    │<─────────────────│                   │                  │
    │                  │                   │                  │
    │  OAuth authorize (?upstream=github)  │                  │
    │─────────────────────────────────────>│                  │
    │                  │                   │  redirect to     │
    │                  │                   │  GitHub OAuth    │
    │                  │                   │─────────────────>│
    │                  │                   │                  │
    │                  │                   │  callback        │
    │                  │                   │<─────────────────│
    │  token           │                   │                  │
    │<─────────────────────────────────────│                  │
    │                  │                   │                  │
    │  tools/call (with token)             │                  │
    │─────────────────>│                   │                  │
    │                  │ (exchanges token  │                  │
    │                  │  for upstream     │                  │
    │                  │  GitHub token)    │                  │
    │  result          │                   │                  │
    │<─────────────────│                   │                  │
```

## Key Design Decisions

### HTTP 401, Not JSON-RPC Error

When vMCP detects a missing upstream token, it must return a raw **HTTP 401**,
not a JSON-RPC error wrapped in an HTTP 200. This is critical because MCP
client SDKs trigger auth retry logic based on the HTTP status code:

- TypeScript SDK: `send()` checks `response.status === 401`, extracts
  `resource_metadata` from `WWW-Authenticate`, runs full OAuth flow, retries.
- Python SDK: `OAuthClientProvider` hooks into httpx's auth flow at the HTTP
  level. A 401 triggers `async_auth_flow` which extracts `resource_metadata`
  and re-authenticates.

If the 401 is buried inside a JSON-RPC error with HTTP 200 status, clients
never see it.

### Two Layers of Auth

vMCP has two distinct authentication boundaries:

1. **Incoming auth** (client → vMCP): "Is this client authenticated to vMCP?"
   Handled by the existing `TokenValidator` middleware. Returns a standard 401
   with vMCP's own `resource_metadata` URL if the client has no token.

2. **Upstream auth** (vMCP → backend): "Do I have upstream tokens for this
   user and this backend's upstream provider?" This is the new layer. After
   the client is authenticated to vMCP, the router checks whether upstream
   tokens are available. If not, it returns a 401 with an upstream-specific
   `resource_metadata` URL.

The client handles both identically — see 401, follow `resource_metadata`, do
OAuth. But each 401 points to different metadata that routes through a
different provider.

### Per-Upstream Metadata Paths

Each upstream provider gets its own well-known metadata endpoint:

```
/.well-known/oauth-protected-resource/upstream/github
/.well-known/oauth-protected-resource/upstream/atlassian
/.well-known/oauth-protected-resource/upstream/slack
```

Each returns a `RFC9728AuthInfo` document with an `authorization_servers` list
containing the authserver URL parameterized for that upstream. The path
structure follows RFC 9728's convention of appending resource-specific path
segments to the well-known prefix.

### No Caching Staleness

Because the `resource_metadata` URL is returned per-response in the
`WWW-Authenticate` header, there is no caching problem. Each 401 carries the
exact metadata URL the client needs for that specific failure. Contrast this
with a single static metadata endpoint that must somehow represent all possible
upstreams simultaneously.

## SDK Compatibility

Verified against current MCP SDK implementations:

| SDK | Auto-retry 401 on tool call? | Parses `resource_metadata`? | Re-authenticates? |
|-----|-----|-----|-----|
| TypeScript (`@modelcontextprotocol/sdk`) | Yes (with circuit breaker) | Yes | Yes |
| Python (`mcp`) | Yes (if `OAuthClientProvider` wired in) | Yes | Yes |
| Go (`mark3labs/mcp-go`) | No (returns `OAuthAuthorizationRequiredError`) | No | No |

The TypeScript SDK (used by Claude Desktop) and Python SDK both fully support
this flow. The Go SDK surfaces the error for the caller to handle
programmatically.

## Alternatives Considered

### Rich Authorization Requests (RFC 9396)

RAR would be the ideal solution — `authorization_details` in the
`WWW-Authenticate` header could express exactly which upstream provider and
what permissions are needed, with full structured metadata:

```
WWW-Authenticate: Bearer error="insufficient_scope",
  authorization_details=[{"type":"upstream_auth","provider":"github","actions":["repo:read"]}]
```

**Why we rejected it**: Zero support across the MCP ecosystem today.

- The MCP specification (all versions including draft) does not reference
  RFC 9396.
- No MCP SDK (TypeScript, Python, or Go) sends, receives, or parses
  `authorization_details`.
- There is an open issue on the spec repo
  ([modelcontextprotocol/specification#1670](https://github.com/modelcontextprotocol/specification/issues/1670))
  requesting RAR support, but a maintainer flagged it as a "candidate for
  profiles/extensions" with no timeline.

RAR remains a good long-term option if the MCP ecosystem adopts it. The
per-upstream metadata path approach is compatible — we could add RAR support
later without breaking the existing flow.

### Scope-Based Step-Up (403 + `insufficient_scope`)

The TypeScript and Python SDKs handle 403 responses with
`error="insufficient_scope"` by extracting the `scope` parameter and
re-authenticating with expanded scopes:

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="upstream:github"
```

**Why we rejected it**: Scopes are flat strings. Encoding upstream identity in
a scope like `upstream:github` stretches the semantics of OAuth scopes beyond
their intended use. It works mechanically but is less clean than encoding the
upstream in the URL path, where it is invisible to the client and fully within
the server's control.

### Static Metadata With Client-Side Logic

A single `/.well-known/oauth-protected-resource` endpoint could list multiple
authorization servers, with the client choosing the right one based on context.

**Why we rejected it**: This requires client-side awareness of upstream
providers, which violates the principle that clients should only know about
vMCP. It also requires MCP SDK changes and is not compatible with the current
spec.

## Implementation Outline

### Components to Modify

1. **Per-upstream metadata handler** (new): Register handlers at
   `/.well-known/oauth-protected-resource/upstream/{name}` on the vMCP HTTP
   server. Each handler returns a `RFC9728AuthInfo` document with
   `authorization_servers` pointing to the authserver parameterized for that
   upstream.

2. **Upstream token check** (new, in vMCP router): After incoming auth
   succeeds, before calling the backend, check whether upstream tokens exist
   for the authenticated user and the target backend's upstream. If not,
   return HTTP 401 with the upstream-specific `resource_metadata` URL.

3. **Authserver upstream parameter handling**: The authserver must interpret
   the `?upstream=` query parameter to select the correct OAuth provider
   configuration and redirect the user to the right IdP.

4. **Token storage and lookup**: vMCP needs a mechanism to store per-user,
   per-upstream tokens (obtained via the authserver) and look them up when
   routing requests to backends.

### Existing Code Touchpoints

- `pkg/auth/token.go`: `buildWWWAuthenticate()` constructs the header from
  `resourceURL`. The upstream layer would use the same function with a
  different `resourceURL` per upstream.
- `pkg/auth/token.go`: `NewAuthInfoHandler()` creates the metadata endpoint
  handler. A new factory or parameterized version would create upstream-
  specific handlers.
- `pkg/vmcp/server/server.go`: vMCP server setup — register the per-upstream
  well-known handlers.
- `pkg/vmcp/router/`: The router dispatches tool calls to backends. The
  upstream token check would live here or in middleware wrapping the router.
