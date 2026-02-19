# AuthZEN Interface: Rego Primitives for OPA Policy Writers

This document describes the primitives that ToolHive would need to provide to
OPA/Rego policy writers when exposing an AuthZEN-based authorization interface
alongside the existing Cedar authorizer.

## Motivation

ToolHive's Cedar authorizer gives policy writers a typed entity model. When you
write `Action::"call_tool"` or `Tool::"weather"`, the Cedar type system tells
you what you're working with. Entity attributes like `principal.claim_roles` and
`context.arg_location` are discoverable through the type annotations.

With an OPA sidecar behind an AuthZEN interface, `input` is an untyped JSON
blob. Without explicit guidance, policy writers must reverse-engineer the
request shape from ToolHive's source code. This document defines the contract
between ToolHive and the OPA sidecar: the exact shape of the AuthZEN request
for each MCP operation, the vocabulary of actions and resource types, and a set
of Rego helper rules that mirror the experience Cedar policy writers get from
the type system.

## Current Cedar Entity Model

For reference, here is what Cedar policy writers work with today. This is the
contract the Rego primitives need to replicate.

### Entity Types

| Cedar Entity Type | Description | Example |
|-------------------|-------------|---------|
| `Client` | The authenticated principal | `Client::"alice"` |
| `Action` | The MCP operation | `Action::"call_tool"` |
| `Tool` | A tool resource | `Tool::"weather"` |
| `Prompt` | A prompt resource | `Prompt::"greeting"` |
| `Resource` | A data resource | `Resource::"data"` |
| `FeatureType` | Feature category (for list ops) | `FeatureType::"tool"` |

### Actions

| Action | MCP Method | Cedar Entity |
|--------|-----------|--------------|
| Call a tool | `tools/call` | `Action::"call_tool"` |
| Get a prompt | `prompts/get` | `Action::"get_prompt"` |
| Read a resource | `resources/read` | `Action::"read_resource"` |
| List tools | `tools/list` | `Action::"list_tools"` |
| List prompts | `prompts/list` | `Action::"list_prompts"` |
| List resources | `resources/list` | `Action::"list_resources"` |

### Context Conventions

Cedar flattens all attributes into a single context record with prefixes:

- JWT claims: `claim_sub`, `claim_roles`, `claim_groups`, `claim_name`, etc.
- Tool arguments: `arg_location`, `arg_operation`, `arg_value1`, etc.
- Complex argument types get `_present` suffix: `arg_complex_present`

Claims are available on both `principal.*` and `context.*`. Arguments are
available on both `resource.*` and `context.*`.

### Static Entity Data

Cedar supports an `entities_json` store loaded at startup with per-resource
attributes (e.g., `owner`, `sensitivity`). Policies reference these as
`resource.owner`.

## AuthZEN Request Schema

This section defines the exact JSON shape ToolHive would send to the AuthZEN
evaluation endpoint for each MCP operation. This is the most important artifact
for Rego policy writers -- it replaces what Cedar's type system provides
implicitly.

### Request Envelope

All requests follow the
[AuthZEN Access Evaluation API](https://openid.github.io/authzen/) format:

```json
{
  "subject": { ... },
  "action":  { ... },
  "resource": { ... },
  "context": { ... }
}
```

### Subject

The subject is built from the authenticated JWT claims. ToolHive forwards all
claims without the `claim_` prefix used in Cedar (the prefix is a Cedar
convention; AuthZEN uses structured properties instead).

```json
{
  "subject": {
    "type": "client",
    "id": "<sub claim>",
    "properties": {
      "roles": ["analyst", "viewer"],
      "groups": ["engineering"],
      "name": "Alice Smith",
      "email": "alice@example.com"
    }
  }
}
```

- `type`: Always `"client"` (maps to Cedar's `Client` entity type).
- `id`: The JWT `sub` claim (maps to Cedar's `Client::"<id>"`).
- `properties`: All remaining JWT claims, using their original names. Array
  claims (like `roles`, `groups`) are preserved as arrays. Scalar claims
  (`name`, `email`) are preserved as-is.

### Action

```json
{
  "action": {
    "name": "<action_name>",
    "properties": {
      "feature": "<mcp_feature>",
      "operation": "<mcp_operation>"
    }
  }
}
```

- `name`: The Cedar action ID (`call_tool`, `get_prompt`, `read_resource`,
  `list_tools`, `list_prompts`, `list_resources`).
- `properties.feature`: The MCP feature type (`tool`, `prompt`, `resource`).
- `properties.operation`: The MCP operation (`call`, `get`, `read`, `list`).

### Resource

```json
{
  "resource": {
    "type": "<resource_type>",
    "id": "<resource_id>",
    "properties": {
      "name": "<resource_id>",
      "operation": "<operation>",
      "feature": "<feature>"
    }
  }
}
```

- `type`: Maps to Cedar entity types: `tool`, `prompt`, `resource`,
  `feature_type`.
- `id`: The resource identifier (tool name, prompt name, resource URI, or
  feature name for list operations).
- `properties`: Includes the attributes that Cedar adds to the resource entity
  (`name`, `operation`, `feature`). For resources with `entities_json`
  attributes, those are also included here (e.g., `owner`, `sensitivity`).

### Context

```json
{
  "context": {
    "arguments": {
      "location": "NYC",
      "units": "metric"
    }
  }
}
```

- `arguments`: The raw tool/prompt arguments, without the `arg_` prefix used
  in Cedar. `null` or absent when there are no arguments.

### Complete Examples

#### tools/call: "weather" tool with arguments

```json
{
  "subject": {
    "type": "client",
    "id": "alice",
    "properties": {
      "roles": ["analyst"],
      "groups": ["engineering"],
      "email": "alice@example.com"
    }
  },
  "action": {
    "name": "call_tool",
    "properties": {
      "feature": "tool",
      "operation": "call"
    }
  },
  "resource": {
    "type": "tool",
    "id": "weather",
    "properties": {
      "name": "weather",
      "operation": "call",
      "feature": "tool"
    }
  },
  "context": {
    "arguments": {
      "location": "NYC",
      "units": "metric"
    }
  }
}
```

#### prompts/get: "greeting" prompt

```json
{
  "subject": {
    "type": "client",
    "id": "alice",
    "properties": {
      "roles": ["user"]
    }
  },
  "action": {
    "name": "get_prompt",
    "properties": {
      "feature": "prompt",
      "operation": "get"
    }
  },
  "resource": {
    "type": "prompt",
    "id": "greeting",
    "properties": {
      "name": "greeting",
      "operation": "get",
      "feature": "prompt"
    }
  },
  "context": {}
}
```

#### resources/read: "sensitive_data" resource

```json
{
  "subject": {
    "type": "client",
    "id": "bob",
    "properties": {
      "roles": ["data_analyst"],
      "clearance_level": 3
    }
  },
  "action": {
    "name": "read_resource",
    "properties": {
      "feature": "resource",
      "operation": "read"
    }
  },
  "resource": {
    "type": "resource",
    "id": "sensitive_data",
    "properties": {
      "name": "sensitive_data",
      "uri": "file://sensitive_data",
      "operation": "read",
      "feature": "resource"
    }
  },
  "context": {}
}
```

#### tools/list: listing available tools

```json
{
  "subject": {
    "type": "client",
    "id": "alice",
    "properties": {
      "roles": ["user"]
    }
  },
  "action": {
    "name": "list_tools",
    "properties": {
      "feature": "tool",
      "operation": "list"
    }
  },
  "resource": {
    "type": "feature_type",
    "id": "tool",
    "properties": {
      "type": "tool",
      "operation": "list",
      "feature": "tool"
    }
  },
  "context": {}
}
```

## Rego Constants Library

This package defines the vocabulary of the ToolHive authorization domain. It
replaces what Cedar entity type names provide implicitly.

```rego
package toolhive.mcp

# Actions -- these are the values that appear in input.action.name
action_call_tool      := "call_tool"
action_get_prompt     := "get_prompt"
action_read_resource  := "read_resource"
action_list_tools     := "list_tools"
action_list_prompts   := "list_prompts"
action_list_resources := "list_resources"

# Resource types -- these are the values that appear in input.resource.type
resource_type_tool         := "tool"
resource_type_prompt       := "prompt"
resource_type_resource     := "resource"
resource_type_feature_type := "feature_type"

# MCP features
feature_tool     := "tool"
feature_prompt   := "prompt"
feature_resource := "resource"

# MCP operations
operation_call := "call"
operation_get  := "get"
operation_read := "read"
operation_list := "list"
```

## Rego Helper Rules

This package provides helper rules that mirror the patterns Cedar policy writers
use through entity types and attribute access. Without these, every policy
reinvents the same `input.subject.properties.roles` traversals.

```rego
package toolhive.helpers

import rego.v1
import data.toolhive.mcp

# ─── Subject helpers ──────────────────────────────────────────────

# Check if the subject has a specific role.
# Cedar equivalent: principal.claim_roles.contains("admin")
has_role(role) if {
    some r in input.subject.properties.roles
    r == role
}

# Check if the subject belongs to a specific group.
# Cedar equivalent: context.claim_groups.contains("engineering")
has_group(group) if {
    some g in input.subject.properties.groups
    g == group
}

# Check if the subject has a specific ID.
# Cedar equivalent: principal == Client::"user123"
subject_is(id) if {
    input.subject.id == id
}

# Return the subject's ID.
subject_id := input.subject.id

# Return a named property from the subject.
subject_prop(name) := input.subject.properties[name]

# ─── Action helpers ───────────────────────────────────────────────

# True when the action is a tool call.
# Cedar equivalent: action == Action::"call_tool"
is_tool_call if {
    input.action.name == mcp.action_call_tool
}

# True when the action is a prompt get.
# Cedar equivalent: action == Action::"get_prompt"
is_prompt_get if {
    input.action.name == mcp.action_get_prompt
}

# True when the action is a resource read.
# Cedar equivalent: action == Action::"read_resource"
is_resource_read if {
    input.action.name == mcp.action_read_resource
}

# True when the action is any list operation.
is_list_operation if {
    startswith(input.action.name, "list_")
}

# ─── Resource helpers ─────────────────────────────────────────────

# Check if the resource has a specific ID.
# Cedar equivalent: resource == Tool::"weather"
resource_is(name) if {
    input.resource.id == name
}

# Check if the resource has a specific type.
resource_type_is(t) if {
    input.resource.type == t
}

# Return a named property from the resource.
resource_prop(name) := input.resource.properties[name]

# ─── Argument helpers ─────────────────────────────────────────────

# Return the value of a tool/prompt argument.
# Cedar equivalent: context.arg_<name>
arg(name) := input.context.arguments[name]

# True when a specific argument is present.
has_arg(name) if {
    input.context.arguments[name]
}
```

## Example Policies: Cedar to Rego Translations

These examples show how common Cedar policy patterns translate to Rego using
the helpers above. Each example includes the Cedar policy for comparison.

### Permit all (open policy)

**Cedar:**
```
permit(principal, action, resource);
```

**Rego:**
```rego
package authz

default decision := true
```

### Role-based tool access

**Cedar:**
```
permit(principal, action == Action::"call_tool", resource == Tool::"weather")
when { principal.claim_roles.contains("analyst") };
```

**Rego:**
```rego
package authz

import data.toolhive.helpers as h

default decision := false

decision if {
    h.is_tool_call
    h.resource_is("weather")
    h.has_role("analyst")
}
```

### Admin access to all tools

**Cedar:**
```
permit(principal, action == Action::"call_tool", resource) when {
    principal.claim_roles.contains("admin")
};
```

**Rego:**
```rego
decision if {
    h.is_tool_call
    h.has_role("admin")
}
```

### Specific client access

**Cedar:**
```
permit(principal == Client::"alice", action == Action::"call_tool", resource);
```

**Rego:**
```rego
decision if {
    h.is_tool_call
    h.subject_is("alice")
}
```

### Argument-based restrictions

**Cedar:**
```
permit(principal, action == Action::"call_tool", resource == Tool::"weather")
when { context.arg_location == "New York" || context.arg_location == "London" };
```

**Rego:**
```rego
decision if {
    h.is_tool_call
    h.resource_is("weather")
    h.arg("location") in {"New York", "London"}
}
```

### Combining claims and arguments

**Cedar:**
```
permit(principal, action == Action::"call_tool", resource == Tool::"sensitive_data")
when {
    principal.claim_roles.contains("data_analyst") &&
    resource.arg_data_level <= principal.claim_clearance_level
};
```

**Rego:**
```rego
decision if {
    h.is_tool_call
    h.resource_is("sensitive_data")
    h.has_role("data_analyst")
    h.arg("data_level") <= h.subject_prop("clearance_level")
}
```

### Owner-based access (with OPA data store)

**Cedar:**
```
permit(principal, action == Action::"call_tool", resource) when {
    resource.owner == principal.claim_sub
};
```

**Rego (option A -- resource properties in AuthZEN request):**
```rego
decision if {
    h.is_tool_call
    h.resource_prop("owner") == h.subject_id
}
```

**Rego (option B -- resource data in OPA's data store):**
```rego
decision if {
    h.is_tool_call
    data.resources[input.resource.id].owner == h.subject_id
}
```

### Forbid takes precedence (default deny with explicit forbid)

**Cedar:**
```
permit(principal, action == Action::"call_tool", resource);
forbid(principal, action == Action::"call_tool", resource == Tool::"dangerous");
```

**Rego:**
```rego
default decision := false

decision if {
    h.is_tool_call
    not denied
}

denied if {
    h.is_tool_call
    h.resource_is("dangerous")
}
```

### Group-based access to prompts

**Cedar:**
```
permit(principal, action == Action::"get_prompt", resource == Prompt::"internal_brief")
when { context.claim_groups.contains("engineering") };
```

**Rego:**
```rego
decision if {
    h.is_prompt_get
    h.resource_is("internal_brief")
    h.has_group("engineering")
}
```

### List filtering (response filtering pattern)

In ToolHive, list operations are always allowed but responses are filtered
based on the call/get/read policies. The same pattern applies with OPA: the
PDP evaluates each individual item against the policy during response filtering.

## Static Entity Data: The entities_json Gap

Cedar's `entities_json` is a static store of per-resource attributes loaded at
startup. For example:

```json
[
  {"uid": "Tool::weather", "attrs": {"owner": "alice", "sensitivity": "low"}},
  {"uid": "Tool::database_query", "attrs": {"owner": "dba_team", "sensitivity": "high"}}
]
```

Policies reference these as `resource.owner` or `resource.sensitivity`.

With an OPA sidecar, there are two approaches for handling this data:

### Option A: Include in AuthZEN resource.properties

ToolHive loads the entity data at startup and includes it in every AuthZEN
request under `resource.properties`. The sidecar doesn't need its own data
store.

**Pros:** Simple, no additional infrastructure. Policy writers access data
through `input.resource.properties.*` or via `h.resource_prop("owner")`.

**Cons:** ToolHive must know about all resource attributes. Attributes must be
configured in ToolHive's config file. Cannot be updated independently of
ToolHive.

### Option B: OPA data store

The OPA sidecar manages its own data documents (via bundles, the data API, or
mounted files). Resource attributes live in `data.resources.*`.

```json
{
  "resources": {
    "weather": {"owner": "alice", "sensitivity": "low"},
    "database_query": {"owner": "dba_team", "sensitivity": "high"}
  }
}
```

**Pros:** Sidecar owns its data. Can be updated without touching ToolHive.
Supports richer data models (hierarchies, relationships).

**Cons:** Requires OPA data pipeline setup (bundles, mounts, or API calls).
Policy writers must understand OPA's data model.

### Recommendation

Start with Option A for simplicity. It mirrors the Cedar `entities_json`
experience -- configure attributes alongside policies, access them through the
same `input` object. If the OPA deployment grows to need independent data
management, migrate to Option B. The helper rules abstract the access pattern,
so policies can be updated to use `data.*` paths without changing the overall
structure.

## Relationship to Existing Authorizers

This design **does not replace** the existing Cedar or HTTP PDP authorizers. It
describes a third authorizer type (`authzenv1`) that would:

1. Implement the `authorizers.Authorizer` interface
   (`pkg/authz/authorizers/core.go`).
2. Map `AuthorizeWithJWTClaims` parameters to the AuthZEN request schema
   described above.
3. Send the AuthZEN request to a configured PDP endpoint (e.g., an OPA sidecar
   running with a decision endpoint).
4. Return the PDP's boolean decision.

The Rego constants, helpers, and example policies described here would be
shipped as a reusable Rego library that policy writers import into their
policies. ToolHive itself doesn't execute Rego -- it just sends the AuthZEN
JSON and reads the decision.

### Comparison with httpv1

The existing `httpv1` authorizer uses a PORC (Principal-Operation-Resource-Context)
model that is similar but distinct from AuthZEN:

| Aspect | httpv1 (PORC) | AuthZEN |
|--------|---------------|---------|
| Subject | `principal.sub`, `principal.roles` | `subject.id`, `subject.properties.roles` |
| Action | `operation` (string: `mcp:tool:call`) | `action.name` (`call_tool`) + `action.properties` |
| Resource | `resource` (MRN string) | `resource.type` + `resource.id` + `resource.properties` |
| Context | `context.mcp.args` | `context.arguments` |
| Claim mapping | Configurable (MPE/standard) | Standardized in properties |
| Endpoint | `POST /decision` | `POST /access/v1/evaluation` (AuthZEN spec) |

AuthZEN provides a richer, more structured model with typed subjects, actions,
and resources. The PORC model encodes everything into flat strings and a
freeform context. For OPA/Rego, the structured AuthZEN model is more natural
because Rego excels at traversing nested JSON structures.
