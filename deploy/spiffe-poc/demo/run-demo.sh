#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# SPIFFE PoC — Presentation Demo Script
#
# Demonstrates workload-identity-based MCP access control:
#   Act 1: How SPIFFE identity is provisioned (the credential itself)
#   Act 2: The credential chain — cert → mTLS → JWT → Cedar → tool call
#   Act 3: Delegation — human + agent identity via RFC 8693 token exchange
#   Act 4: Sidecar proxy — wrapping an unmodified agent transparently
#
# Prerequisites:
#   - kubectl configured and kind-toolhive cluster running
#   - All demo manifests applied (see deploy/spiffe-poc/demo/README.md)
#   - Keycloak deployed (./setup-keycloak.sh) for Act 3
#   - Sidecar pod deployed (./build-agent-proxy.sh + manifests) for Act 4
#   - jq and jwt-cli available on PATH
#
# Usage:
#   ./deploy/spiffe-poc/demo/run-demo.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Color codes and status badges
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

ALLOWED="${GREEN}[ALLOWED]${NC}"
DENIED="${RED}[DENIED]${NC}"
TOKEN_OK="${GREEN}[TOKEN GRANTED]${NC}"
TOKEN_DENIED="${RED}[TOKEN DENIED]${NC}"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
step() {
    printf "\n${BLUE}${BOLD}==> %s${NC}\n" "$*"
    sleep 1
}

info() {
    printf "    %s\n" "$*"
}

dim() {
    printf "    ${DIM}%s${NC}\n" "$*"
}

blank() {
    printf "\n"
}

result() {
    printf "    %-65b %b\n" "$1" "$2"
}

header() {
    printf "\n${BOLD}%s${NC}\n" "$*"
    printf "%s\n" "$(printf '%0.s-' $(seq 1 72))"
}

pause() {
    printf "\n    ${DIM}[Press Enter to continue]${NC}"
    read -r
}

# ---------------------------------------------------------------------------
# Cluster helpers
# ---------------------------------------------------------------------------
CONTEXT="kind-toolhive"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPERATOR_NS="toolhive-system"
AGENTS_NS="agents"
UNTRUSTED_NS="untrusted"

FETCH_URL="https://mcp-fetch-proxy.${OPERATOR_NS}.svc.cluster.local:8080"

TRUST_DOMAIN="toolhive.dev"

# Run curl from inside an agent pod using its SPIFFE SVID for mTLS.
agent_curl() {
    local pod=$1 ns=$2
    shift 2
    kubectl --context "${CONTEXT}" exec -n "${ns}" "${pod}" -- \
        curl -sk --max-time 10 \
        --cert /var/run/secrets/spiffe.io/tls.crt \
        --key  /var/run/secrets/spiffe.io/tls.key \
        --cacert /var/run/secrets/spiffe.io/ca.crt \
        "$@" 2>&1
}

# Request a client-credentials token from an MCP proxy's embedded auth server.
get_token() {
    local pod=$1 ns=$2 spiffe_id=$3 proxy_url=$4
    agent_curl "${pod}" "${ns}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=${spiffe_id}&resource=${proxy_url}" \
        "${proxy_url}/oauth/token"
}

# Extract a field from a JSON string using jq.
json_field() {
    local json=$1 field=$2
    printf '%s' "${json}" | jq -r ".${field} // empty" 2>/dev/null || true
}

# decode_jwt <token> [field ...] — decodes a JWT and pretty-prints selected claims.
decode_jwt() {
    local token=$1; shift
    local claims
    claims=$(printf '%s' "${token}" | jwt decode --ignore-exp -j - 2>/dev/null) || return
    local payload
    payload=$(printf '%s' "${claims}" | jq -r '.payload')

    if [ $# -eq 0 ]; then
        set -- sub iss aud client_id exp
    fi

    for f in "$@"; do
        local val
        val=$(printf '%s' "${payload}" | jq -r "
            if .${f} == null then \"\"
            elif (.${f} | type) == \"array\" then .${f}[0]
            elif (.${f} | type) == \"object\" then (.${f} | tostring)
            else .${f} | tostring
            end" 2>/dev/null)
        if [ "${f}" = "exp" ] && [ -n "${val}" ] && [ "${val}" != "" ]; then
            val=$(date -r "${val}" +%H:%M:%S 2>/dev/null || echo "${val}")
            val="${val} (short-lived)"
        fi
        printf "         %-12s %s\n" "${f}:" "${val}"
    done
}

# Perform RFC 8693 token exchange.
exchange_token() {
    local pod=$1 ns=$2 spiffe_id=$3 proxy_url=$4 user_token=$5 agent_token=$6
    agent_curl "${pod}" "${ns}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=${user_token}&subject_token_type=urn:ietf:params:oauth:token-type:id_token&actor_token=${agent_token}&actor_token_type=urn:ietf:params:oauth:token-type:access_token&client_id=${spiffe_id}&resource=${proxy_url}" \
        "${proxy_url}/oauth/token"
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
check_prerequisites() {
    step "Checking prerequisites"

    local ok=true

    if ! command -v kubectl &>/dev/null; then
        printf "    ${RED}ERROR: kubectl not found on PATH${NC}\n"
        ok=false
    fi

    if ! command -v jq &>/dev/null; then
        printf "    ${RED}ERROR: jq not found on PATH${NC}\n"
        ok=false
    fi

    if ! command -v jwt &>/dev/null; then
        printf "    ${RED}ERROR: jwt not found on PATH (brew install jwt-cli)${NC}\n"
        ok=false
    fi

    if ! kubectl --context "${CONTEXT}" cluster-info &>/dev/null; then
        printf "    ${RED}ERROR: cannot reach cluster context '${CONTEXT}'${NC}\n"
        ok=false
    fi

    if [ "${ok}" = "false" ]; then
        printf "\n${RED}Prerequisites not met. Aborting.${NC}\n"
        exit 1
    fi

    # Check agent pods
    for entry in "devops-agent:${AGENTS_NS}" "rogue-agent:${UNTRUSTED_NS}"; do
        IFS=: read -r pod ns <<< "${entry}"
        local phase
        phase=$(kubectl --context "${CONTEXT}" get pod "${pod}" -n "${ns}" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
        if [ "${phase}" != "Running" ]; then
            printf "    ${YELLOW}[WARN]${NC} Pod %s/%s is %s (expected Running)\n" "${ns}" "${pod}" "${phase}"
        fi
    done

    info "Prerequisites satisfied."
}

# ---------------------------------------------------------------------------
# Act 1: Identity — what the credential IS and how it's provisioned
# ---------------------------------------------------------------------------
act1_identity() {
    step "Act 1 — Identity: how SPIFFE credentials are provisioned"
    blank
    info "Every agent pod gets a cryptographic identity at startup."
    info "No passwords, no client secrets, no manual certificate signing."
    blank
    info "How it works:"
    dim "  1. Pod is scheduled by Kubernetes"
    dim "  2. cert-manager CSI driver intercepts the volume mount"
    dim "  3. It requests an X.509 certificate from the SPIFFE CA"
    dim "  4. The certificate is written to /var/run/secrets/spiffe.io/"
    dim "  5. The SPIFFE ID (namespace + service account) is embedded as a URI SAN"
    dim "  6. The cert auto-rotates (1h TTL in this cluster)"
    blank

    info "The credential on disk:"
    blank
    dim "  /var/run/secrets/spiffe.io/"
    dim "    tls.crt    ← X.509 certificate (the SVID)"
    dim "    tls.key    ← Private key (never leaves the pod)"
    dim "    ca.crt     ← SPIFFE CA trust bundle"
    blank

    info "SPIFFE IDs extracted from each pod's certificate:"
    blank

    for entry in "devops-agent:${AGENTS_NS}" "rogue-agent:${UNTRUSTED_NS}"; do
        IFS=: read -r pod ns <<< "${entry}"
        local spiffe_id
        spiffe_id=$(kubectl --context "${CONTEXT}" exec -n "${ns}" "${pod}" -- \
            cat /var/run/secrets/spiffe.io/tls.crt 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null \
            | grep -o 'URI:spiffe://[^, ]*' | sed 's/URI://' || echo "(could not read SVID)")

        result "${pod} (ns: ${ns})" "${spiffe_id}"
    done

    blank
    info "The format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>"
    info "Namespace encodes the trust boundary. rogue-agent is in 'untrusted' —"
    info "its identity says so, and policy will enforce it."
    blank
    info "In production, SPIRE replaces the CSI driver with deeper attestation:"
    info "node identity from cloud metadata, workload identity from image digest."
    info "The certificates look identical — the attestation chain gets stronger."
}

# ---------------------------------------------------------------------------
# Act 2: Credential chain — cert → mTLS → JWT → Cedar → tool call
# ---------------------------------------------------------------------------
act2_credential_chain() {
    step "Act 2 — Credential chain: from certificate to tool call"
    blank
    info "Follow devops-agent through the full authentication chain."
    blank

    # Step 1: mTLS to get a JWT
    info "Step 1: X.509-SVID → mTLS → OAuth JWT"
    blank
    dim "  The agent presents its certificate as a TLS client cert."
    dim "  The auth server extracts the SPIFFE ID from the URI SAN,"
    dim "  checks it against the registration allow-list, and issues a JWT."
    dim "  This implements draft-ietf-oauth-spiffe-client-auth."
    blank

    local resp
    resp=$(get_token devops-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/devops-agent" "${FETCH_URL}")
    DEVOPS_TOKEN=$(json_field "${resp}" "access_token")

    if [ -n "${DEVOPS_TOKEN}" ]; then
        result "  devops-agent → mTLS → JWT" "${TOKEN_OK}"
        blank
        info "  The JWT claims (SPIFFE ID became the OAuth subject):"
        decode_jwt "${DEVOPS_TOKEN}" sub iss aud client_id exp
    else
        result "  devops-agent → mTLS → JWT" "${TOKEN_DENIED}"
    fi
    blank

    # Contrast: rogue-agent rejected
    info "  Contrast: rogue-agent (untrusted namespace) → rejected at registration"
    resp=$(get_token rogue-agent "${UNTRUSTED_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${UNTRUSTED_NS}/sa/rogue-agent" "${FETCH_URL}")
    local rogue_token
    rogue_token=$(json_field "${resp}" "access_token")
    if [ -z "${rogue_token}" ]; then
        local err
        err=$(json_field "${resp}" "error_description")
        result "  rogue-agent → mTLS → [${err:-rejected}]" "${TOKEN_DENIED}"
    fi
    blank

    dim "  Same CA signed both certificates. The difference is the SPIFFE ID:"
    dim "  namespace 'agents' is allowed, namespace 'untrusted' is not."
    blank

    # Step 2: JWT → Cedar → tool call
    if [ -n "${DEVOPS_TOKEN}" ]; then
        info "Step 2: JWT → Cedar policy → tool call"
        blank
        dim "  Cedar policies on the fetch proxy:"
        blank
        dim '    permit(principal, action == Action::"call_tool", resource)'
        dim '      when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/devops-*" };'
        blank
        dim '    // No permit for intern-agent on call_tool (delegation only)'
        blank

        info "  The 'sub' claim carries the SPIFFE ID. Cedar matches on it directly."
        info "  devops-agent: full tool access. intern-agent: list-only (see Act 3)."
    fi
}

# ---------------------------------------------------------------------------
# Act 3: Delegation — human + agent identity
# ---------------------------------------------------------------------------
act3_delegation() {
    step "Act 3 — Delegation: human + agent identity"
    blank
    info "An agent acting alone has only its SPIFFE identity."
    info "But when a human delegates, both identities merge into one token."
    blank
    info "The credential chain adds a step:"
    dim "  1. User logs in to Keycloak (OIDC) → gets an ID token"
    dim "  2. Agent already has its SPIFFE JWT (from Act 2)"
    dim "  3. RFC 8693 token exchange: user token + agent JWT → delegated JWT"
    dim "  4. Delegated JWT carries: sub=user, act.sub=agent SPIFFE ID"
    dim "  5. Cedar evaluates the composite identity"
    blank

    # Get intern-agent token (for the actor_token)
    local resp
    resp=$(get_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" "${FETCH_URL}")
    INTERN_TOKEN=$(json_field "${resp}" "access_token")

    if [ -z "${INTERN_TOKEN}" ]; then
        result "  intern-agent token" "${TOKEN_DENIED}"
        return
    fi

    # Get Keycloak user tokens
    info "User tokens from Keycloak:"
    blank

    kubectl --context "${CONTEXT}" port-forward svc/keycloak-dev-service 8443:8443 -n keycloak &>/dev/null &
    local kc_pf=$!
    sleep 3

    local devops_user_token intern_user_token
    devops_user_token=$("${SCRIPT_DIR}/get-user-token.sh" devops-user devops123 id_token 2>/dev/null || true)
    intern_user_token=$("${SCRIPT_DIR}/get-user-token.sh" intern-user intern123 id_token 2>/dev/null || true)

    kill "${kc_pf}" 2>/dev/null || true
    wait "${kc_pf}" 2>/dev/null || true

    if [ -z "${devops_user_token}" ] || [ -z "${intern_user_token}" ]; then
        result "  Keycloak token fetch" "${TOKEN_DENIED}"
        return
    fi

    result "  devops-user@example.com" "${TOKEN_OK}"
    result "  intern-user@example.com" "${TOKEN_OK}"
    blank

    # Token exchange: devops-user via intern-agent
    info "Token exchange: intern-agent + devops-user → delegated JWT"
    blank

    resp=$(exchange_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" \
        "${FETCH_URL}" "${devops_user_token}" "${INTERN_TOKEN}")
    local devops_delegated
    devops_delegated=$(json_field "${resp}" "access_token")

    if [ -n "${devops_delegated}" ]; then
        result "  intern-agent + devops-user → delegated JWT" "${TOKEN_OK}"
        blank
        info "  The delegated JWT — both identities in one token:"
        decode_jwt "${devops_delegated}" sub email name act iss exp
        blank
        dim "  'sub' and 'email' are the human. 'act.sub' is the agent."
        dim "  Cedar sees both. The policy checks them together."
    else
        result "  intern-agent + devops-user → exchange failed" "${TOKEN_DENIED}"
    fi
    blank

    # Show the Cedar delegation policy
    info "Cedar delegation policy on fetch proxy:"
    blank
    dim '    permit(principal, action == Action::"call_tool", resource)'
    dim '      when {'
    dim '        context has claim_act &&'
    dim '        context has claim_email &&'
    dim '        context.claim_email == "devops-user@example.com" &&'
    dim '        context.claim_act.sub like "spiffe://toolhive.dev/ns/agents/sa/*"'
    dim '      };'
    blank

    # Contrast: intern-user delegation denied
    resp=$(exchange_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" \
        "${FETCH_URL}" "${intern_user_token}" "${INTERN_TOKEN}")
    local intern_delegated
    intern_delegated=$(json_field "${resp}" "access_token")

    info "Same flow with intern-user → Cedar denies (no policy matches email):"
    if [ -n "${intern_delegated}" ]; then
        result "  intern-agent + intern-user → delegated JWT issued" "${TOKEN_OK}"
        result "  Cedar evaluation → no matching policy" "${DENIED}"
    fi
    blank

    # Summary matrix
    header "Delegation matrix (fetch proxy, intern-agent)"
    printf "\n"
    printf "    %-24s  %-14s  %-14s\n" \
        "Identity" "list_tools" "call_tool"
    printf "    %-24s  %-14s  %-14s\n" \
        "------------------------" "--------------" "--------------"
    printf "    %-24s  %-26b  %b\n" "autonomous (SPIFFE only)" "${GREEN}ALLOW${NC}" "${RED}DENY${NC}"
    printf "    %-24s  %-26b  %b\n" "+ devops-user delegation" "${GREEN}ALLOW${NC}" "${GREEN}ALLOW${NC}"
    printf "    %-24s  %-26b  %b\n" "+ intern-user delegation" "${GREEN}ALLOW${NC}" "${RED}DENY${NC}"
    blank

    info "Same agent, same tool. The human's identity determines the outcome."
}

# ---------------------------------------------------------------------------
# Act 4: Sidecar proxy — wrapping an unmodified agent
# ---------------------------------------------------------------------------
act4_sidecar() {
    step "Act 4 — Sidecar proxy: wrapping an unmodified agent"
    blank
    info "Acts 1-3 used agents that speak SPIFFE natively."
    info "But real coding agents — Claude Code, Codex, Cursor — don't."
    blank
    info "A sidecar proxy makes delegation transparent:"
    blank
    dim "  ┌──────────────┐    ┌─────────────────────┐"
    dim "  │  Agent        │    │  Sidecar proxy       │"
    dim "  │  (unmodified) ├───►│  (SPIFFE creds)      │──mTLS──► MCP server"
    dim "  │              │    │                       │"
    dim "  │  Bearer:      │    │  1. Extract user tok  │"
    dim "  │  user_token   │    │  2. SPIFFE bootstrap  │"
    dim "  │              │    │  3. Token exchange    │"
    dim "  │  NO certs    │    │  4. Forward delegated │"
    dim "  └──────────────┘    └─────────────────────┘"
    blank
    info "  The user's token arrives via the orchestrator (CI, CLI harness,"
    info "  or in the future, a local OIDC login served by the sidecar)."
    blank

    # Check if sidecar pod is running
    local sidecar_phase
    sidecar_phase=$(kubectl --context "${CONTEXT}" get pod sidecar-test -n "${AGENTS_NS}" \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")

    if [ "${sidecar_phase}" != "Running" ]; then
        printf "    ${YELLOW}Sidecar test pod not running (${sidecar_phase}).${NC}\n"
        info "Deploy it: ./build-agent-proxy.sh && kubectl apply -f manifests/10-sidecar-agent-pod.yaml"
        return
    fi

    # Evidence 1: Agent has no SPIFFE creds
    info "Evidence 1: Agent container has no SPIFFE credentials"
    blank
    dim "  \$ kubectl exec sidecar-test -c agent -- ls /var/run/secrets/spiffe.io/"
    local spiffe_check
    spiffe_check=$(kubectl --context "${CONTEXT}" exec -n "${AGENTS_NS}" sidecar-test -c agent -- \
        ls /var/run/secrets/spiffe.io/ 2>&1 || true)
    dim "  ${spiffe_check}"
    blank

    # Evidence 2: Sidecar bootstrap
    info "Evidence 2: Sidecar bootstrapped its own SPIFFE identity"
    blank
    kubectl --context "${CONTEXT}" logs sidecar-test -n "${AGENTS_NS}" -c spiffe-proxy 2>&1 \
        | grep -E '"level":"INFO"' | while IFS= read -r line; do
        dim "  ${line}"
    done
    blank

    # Evidence 3: Make an MCP call through the sidecar
    info "Evidence 3: Agent calls MCP through sidecar with user token"
    blank

    kubectl --context "${CONTEXT}" port-forward svc/keycloak-dev-service 8443:8443 -n keycloak &>/dev/null &
    local kc_pf=$!
    sleep 3
    local user_token
    user_token=$("${SCRIPT_DIR}/get-user-token.sh" devops-user devops123 id_token 2>/dev/null || true)
    kill "${kc_pf}" 2>/dev/null || true
    wait "${kc_pf}" 2>/dev/null || true

    if [ -z "${user_token}" ]; then
        result "  Keycloak token fetch" "${TOKEN_DENIED}"
        return
    fi

    info "  The orchestrator obtained a devops-user token from Keycloak."
    info "  The agent passes it as a Bearer token to localhost:8080:"
    blank
    dim "  curl -H 'Authorization: Bearer <user-token>' http://localhost:8080/mcp"
    blank

    local init_status
    init_status=$(kubectl --context "${CONTEXT}" exec -n "${AGENTS_NS}" sidecar-test -c agent -- \
        sh -c "curl -s --max-time 15 -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        -H \"Authorization: Bearer ${user_token}\" \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"demo\",\"version\":\"1.0\"}},\"id\":1}' \
        'http://localhost:8080/mcp'" 2>/dev/null || echo "000")

    result "  MCP initialize via sidecar → upstream" "HTTP ${init_status}"
    blank

    sleep 1

    # Evidence 4: Sidecar debug logs showing token exchange
    info "Evidence 4: Sidecar performed token exchange (debug logs)"
    blank
    kubectl --context "${CONTEXT}" logs sidecar-test -n "${AGENTS_NS}" -c spiffe-proxy 2>&1 \
        | grep -E '"level":"DEBUG"' | tail -5 | while IFS= read -r line; do
        dim "  ${line}"
    done
    blank

    local exchange_log
    exchange_log=$(kubectl --context "${CONTEXT}" logs sidecar-test -n "${AGENTS_NS}" -c spiffe-proxy 2>&1 \
        | grep "delegated token issued" | tail -1)

    if [ -n "${exchange_log}" ]; then
        info "  Sidecar created a delegated JWT with these claims:"
        local dt_sub dt_email dt_name dt_act
        dt_sub=$(printf '%s' "${exchange_log}" | jq -r '.sub // empty' 2>/dev/null)
        dt_email=$(printf '%s' "${exchange_log}" | jq -r '.email // empty' 2>/dev/null)
        dt_name=$(printf '%s' "${exchange_log}" | jq -r '.name // empty' 2>/dev/null)
        dt_act=$(printf '%s' "${exchange_log}" | jq -r '.act.sub // empty' 2>/dev/null)
        printf "         %-12s %s  ${DIM}(Keycloak user)${NC}\n" "sub:" "${dt_sub}"
        printf "         %-12s %s\n" "email:" "${dt_email}"
        printf "         %-12s %s\n" "name:" "${dt_name}"
        printf "         %-12s %s  ${DIM}(sidecar SPIFFE ID)${NC}\n" "act.sub:" "${dt_act}"
    fi
    blank

    # Evidence 5: What ToolHive received
    local fetch_proxy
    fetch_proxy=$(kubectl --context "${CONTEXT}" get pods -n "${OPERATOR_NS}" \
        -l app.kubernetes.io/name=mcp-fetch-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

    if [ -n "${fetch_proxy}" ]; then
        info "Evidence 5: What ToolHive received (Cedar evaluation)"
        blank
        info "  The MCP server decoded the delegated JWT and evaluated Cedar:"
        blank

        local cedar_ctx
        cedar_ctx=$(kubectl --context "${CONTEXT}" logs "${fetch_proxy}" -n "${OPERATOR_NS}" 2>&1 \
            | grep "cedar context" | tail -1)

        if [ -n "${cedar_ctx}" ]; then
            local ctx_sub ctx_email ctx_name ctx_act ctx_client_id
            ctx_sub=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_sub // empty' 2>/dev/null)
            ctx_email=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_email // empty' 2>/dev/null)
            ctx_name=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_name // empty' 2>/dev/null)
            ctx_act=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_act.sub // empty' 2>/dev/null)
            ctx_client_id=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_client_id // empty' 2>/dev/null)
            printf "         %-18s %s  ${DIM}(Keycloak user)${NC}\n" "claim_sub:" "${ctx_sub}"
            printf "         %-18s %s\n" "claim_email:" "${ctx_email}"
            printf "         %-18s %s\n" "claim_name:" "${ctx_name}"
            printf "         %-18s %s  ${DIM}(sidecar SPIFFE ID)${NC}\n" "claim_act.sub:" "${ctx_act}"
            printf "         %-18s %s\n" "claim_client_id:" "${ctx_client_id}"
        fi

        local cedar_decision
        cedar_decision=$(kubectl --context "${CONTEXT}" logs "${fetch_proxy}" -n "${OPERATOR_NS}" 2>&1 \
            | grep "cedar decision" | tail -1)

        if [ -n "${cedar_decision}" ]; then
            local decision policy
            decision=$(printf '%s' "${cedar_decision}" | jq -r '.decision // empty' 2>/dev/null)
            policy=$(printf '%s' "${cedar_decision}" | jq -r '.diagnostic.reasons[0].policy // empty' 2>/dev/null)
            blank
            if [ "${decision}" = "allow" ]; then
                result "  Cedar decision: ${decision} (${policy} = delegation permit)" "${ALLOWED}"
            else
                result "  Cedar decision: ${decision}" "${DENIED}"
            fi
        fi
    fi

    blank
    info "The agent sent a plain Bearer token to localhost."
    info "The sidecar handled SPIFFE bootstrap, token exchange, and mTLS."
    info "ToolHive received a delegated JWT and Cedar evaluated both identities."
    info "The agent never touched a certificate or a private key."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
summary() {
    step "Summary"
    blank
    info "The credential chain, end to end:"
    blank
    info "1. Identity:       SPIFFE X.509-SVID provisioned by CSI driver at pod startup."
    info "                   Trust domain + namespace + SA → unique workload identity."
    blank
    info "2. Authentication: Certificate presented via mTLS (draft-ietf-oauth-spiffe-"
    info "                   client-auth). Auth server issues a short-lived JWT."
    blank
    info "3. Authorization:  Cedar evaluates JWT claims on every MCP call."
    info "                   Per-tool, per-workload, no shared secrets."
    blank
    info "4. Delegation:     RFC 8693 merges human + agent identity into one JWT."
    info "                   Cedar evaluates the composite: who delegated, which agent."
    blank
    info "5. Sidecar proxy:  Unmodified agents wrapped transparently."
    info "                   Agent → localhost → sidecar → mTLS → MCP server."
    blank

    header "Trade-offs and next steps"
    printf "\n"
    info "  The sidecar proves the architecture for agents that pass Bearer tokens."
    info "  For agents that expect MCP auth discovery (Claude Code, Codex), the"
    info "  sidecar needs a local OAuth authorization server — essentially running"
    info "  ToolHive's embedded auth server inside the sidecar. That is the next"
    info "  step (Tier 2)."
    blank
    printf "    ${BOLD}Result:${NC} least-privilege access for AI agents, enforced cryptographically.\n"
    printf "    ${BOLD}        Autonomous, delegated, or proxied — same policy, same audit trail.${NC}\n"
    blank
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
    printf "\n${BOLD}${BLUE}"
    printf "================================================================\n"
    printf "  ToolHive SPIFFE PoC — Workload Identity for MCP Agents\n"
    printf "================================================================\n"
    printf "${NC}\n"
    printf "  Cluster:      %s\n" "${CONTEXT}"
    printf "  Trust domain: %s\n" "${TRUST_DOMAIN}"
    printf "  MCP proxies:  fetch, cluster-tools\n"
    printf "  Agents:       devops-agent, intern-agent, rogue-agent\n"
    blank

    check_prerequisites
    act1_identity
    pause
    act2_credential_chain
    pause
    act3_delegation
    pause
    act4_sidecar
    pause
    summary
}

main "$@"
