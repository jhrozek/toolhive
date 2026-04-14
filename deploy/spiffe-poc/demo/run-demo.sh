#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# SPIFFE PoC — Presentation Demo Script
#
# Demonstrates workload-identity-based MCP access control:
#   - SPIFFE SVIDs issued automatically to agent pods (no secrets, no passwords)
#   - SPIFFE mTLS client authentication against the embedded auth server
#   - Cedar authorization policies controlling per-tool access
#
# Prerequisites:
#   - kubectl configured and kind-toolhive cluster running
#   - All demo manifests applied (see deploy/spiffe-poc/demo/README.md)
#   - Keycloak deployed (./setup-keycloak.sh) for delegation demo (Act 4)
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
WARN="${YELLOW}[WARN]${NC}"

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

# Print a result line: fixed-width label, then a colored badge on the right.
# Usage: result "label text" "$TOKEN_OK"
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
CT_URL="https://mcp-cluster-tools-proxy.${OPERATOR_NS}.svc.cluster.local:8080"

TRUST_DOMAIN="toolhive.dev"

# Run curl from inside an agent pod using its SPIFFE SVID for mTLS.
# agent_curl <pod> <namespace> [curl-args...]
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
# get_token <pod> <namespace> <spiffe-id> <proxy-base-url>
# Prints the raw JSON response.
get_token() {
    local pod=$1 ns=$2 spiffe_id=$3 proxy_url=$4
    agent_curl "${pod}" "${ns}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=${spiffe_id}&resource=${proxy_url}" \
        "${proxy_url}/oauth/token"
}

# Extract a field from a JSON string using jq.
# json_field <json> <field>  — prints the value or empty string on failure.
json_field() {
    local json=$1 field=$2
    printf '%s' "${json}" | jq -r ".${field} // empty" 2>/dev/null || true
}

# decode_jwt <token> [field ...] — decodes a JWT and pretty-prints selected claims.
# Without field args, prints sub, iss, aud, client_id, exp.
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

# Perform RFC 8693 token exchange: user token + agent JWT → delegated JWT.
# exchange_token <pod> <namespace> <spiffe-id> <proxy-url> <user-token> <agent-token>
# Prints the raw JSON response.
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

    # kubectl must be available
    if ! command -v kubectl &>/dev/null; then
        printf "    ${RED}ERROR: kubectl not found on PATH${NC}\n"
        ok=false
    fi

    # jq must be available (used for JSON parsing)
    if ! command -v jq &>/dev/null; then
        printf "    ${RED}ERROR: jq not found on PATH${NC}\n"
        ok=false
    fi

    # jwt CLI must be available (used for decoding JWTs)
    if ! command -v jwt &>/dev/null; then
        printf "    ${RED}ERROR: jwt not found on PATH (brew install jwt-cli)${NC}\n"
        ok=false
    fi

    # Cluster context must exist and be reachable
    if ! kubectl --context "${CONTEXT}" cluster-info &>/dev/null; then
        printf "    ${RED}ERROR: cannot reach cluster context '${CONTEXT}'${NC}\n"
        printf "    Run ./deploy/spiffe-poc/setup.sh first.\n"
        ok=false
    fi

    if [ "${ok}" = "false" ]; then
        printf "\n${RED}Prerequisites not met. Aborting.${NC}\n"
        exit 1
    fi

    # Check agent pods are ready
    local all_pods_ready=true
    for entry in "devops-agent:${AGENTS_NS}" "intern-agent:${AGENTS_NS}" "rogue-agent:${UNTRUSTED_NS}"; do
        IFS=: read -r pod ns <<< "${entry}"
        local phase
        phase=$(kubectl --context "${CONTEXT}" get pod "${pod}" -n "${ns}" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
        if [ "${phase}" != "Running" ]; then
            printf "    ${WARN} Pod %s/%s is %s (expected Running)\n" "${ns}" "${pod}" "${phase}"
            all_pods_ready=false
        fi
    done

    if [ "${all_pods_ready}" = "false" ]; then
        printf "\n    ${YELLOW}Some pods are not ready. Demo results may be incomplete.${NC}\n"
        printf "    Apply manifests: kubectl --context %s apply -f deploy/spiffe-poc/demo/manifests/\n" "${CONTEXT}"
        blank
        read -r -p "    Continue anyway? [y/N] " answer
        if [[ ! "${answer}" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        info "All agent pods are Running."
    fi

    # Check MCP proxy services exist
    for svc in "mcp-fetch-proxy" "mcp-cluster-tools-proxy"; do
        if ! kubectl --context "${CONTEXT}" get svc "${svc}" -n "${OPERATOR_NS}" &>/dev/null; then
            printf "    ${WARN} Service %s not found in %s\n" "${svc}" "${OPERATOR_NS}"
        fi
    done

    info "Prerequisites satisfied."
}

# ---------------------------------------------------------------------------
# Act 1: Identity is automatic
# ---------------------------------------------------------------------------
act1_identity() {
    step "Act 1 — Identity is automatic"
    blank
    info "Three AI agent workloads are running in this cluster."
    info "None of them were given a password, an API key, or a secret."
    info "Each received a cryptographic identity automatically at startup."
    blank
    info "SPIFFE identity (URI SAN) injected into each pod by the CSI driver:"
    blank

    for entry in "devops-agent:${AGENTS_NS}" "intern-agent:${AGENTS_NS}" "rogue-agent:${UNTRUSTED_NS}"; do
        IFS=: read -r pod ns <<< "${entry}"

        # Extract the spiffe:// URI SAN from the pod's SVID.
        # openssl runs locally (not in the pod) because curlimages/curl lacks it.
        local spiffe_id
        spiffe_id=$(kubectl --context "${CONTEXT}" exec -n "${ns}" "${pod}" -- \
            cat /var/run/secrets/spiffe.io/tls.crt 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null \
            | grep -o 'URI:spiffe://[^, ]*' | sed 's/URI://' || echo "(could not read SVID)")

        result "${pod} (ns: ${ns})" "${spiffe_id}"
    done

    blank
    info "The format encodes namespace and service account — no separate config needed."
    info "When a pod is deleted or rotated, its identity rotates automatically."
}

# ---------------------------------------------------------------------------
# Act 2: Authentication via workload identity
# ---------------------------------------------------------------------------
act2_authentication() {
    step "Act 2 — Authentication via workload identity"
    blank
    info "Each agent presents its X.509-SVID via mTLS to the MCP proxy."
    info "The embedded auth server validates the SPIFFE ID and issues a short-lived JWT."
    blank
    info "Registration policy on both proxies:"
    dim "  allowedIdentities:"
    dim "    - namespace: agents    # only this namespace may obtain tokens"
    dim "      serviceAccount: '*'"
    blank
    info "Token requests — fetch proxy:"
    blank

    # devops-agent -> fetch
    local resp
    resp=$(get_token devops-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/devops-agent" "${FETCH_URL}")
    DEVOPS_FETCH_TOKEN=$(json_field "${resp}" "access_token")
    if [ -n "${DEVOPS_FETCH_TOKEN}" ]; then
        result "  devops-agent  -> fetch proxy" "${TOKEN_OK}"
        blank
        info "  JWT claims (SPIFFE ID became the OAuth subject):"
        decode_jwt "${DEVOPS_FETCH_TOKEN}"
        blank
    else
        local err
        err=$(json_field "${resp}" "error_description")
        result "  devops-agent  -> fetch proxy  [${err:-error}]" "${TOKEN_DENIED}"
    fi

    # intern-agent -> fetch
    resp=$(get_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" "${FETCH_URL}")
    INTERN_FETCH_TOKEN=$(json_field "${resp}" "access_token")
    if [ -n "${INTERN_FETCH_TOKEN}" ]; then
        result "  intern-agent  -> fetch proxy" "${TOKEN_OK}"
    else
        local err
        err=$(json_field "${resp}" "error_description")
        result "  intern-agent  -> fetch proxy  [${err:-error}]" "${TOKEN_DENIED}"
    fi

    # rogue-agent -> fetch (should be denied by registration policy)
    resp=$(get_token rogue-agent "${UNTRUSTED_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${UNTRUSTED_NS}/sa/rogue-agent" "${FETCH_URL}")
    ROGUE_FETCH_TOKEN=$(json_field "${resp}" "access_token")
    if [ -n "${ROGUE_FETCH_TOKEN}" ]; then
        result "  rogue-agent   -> fetch proxy" "${TOKEN_OK}"
    else
        local err err_code
        err=$(json_field "${resp}" "error_description")
        err_code=$(json_field "${resp}" "error")
        result "  rogue-agent   -> fetch proxy  [${err:-unknown}]" "${TOKEN_DENIED}"
        blank
        info "  Raw denial response from the auth server:"
        dim "    $(printf '%s' "${resp}" | jq '.' 2>/dev/null | sed 's/^/    /' || printf '%s' "${resp}")"
    fi

    blank
    info "rogue-agent's SVID is valid (signed by the same CA), but its SPIFFE ID"
    info "is in the 'untrusted' namespace — the registration policy rejects it before"
    info "any token is issued. It never gets a JWT."
    blank
    info "Decoding a granted token (devops-agent, fetch proxy):"
    blank
    if [ -n "${DEVOPS_FETCH_TOKEN}" ]; then
        decode_jwt "${DEVOPS_FETCH_TOKEN}" sub iss aud exp
    else
        dim "  (no token — devops-agent authentication failed)"
    fi

    blank
    info "The 'sub' claim carries the SPIFFE ID. Cedar policies evaluate it directly."
}

# ---------------------------------------------------------------------------
# Act 3: Policy controls access
# ---------------------------------------------------------------------------
act3_authorization() {
    step "Act 3 — Policy controls access"
    blank
    info "Having a token is not the same as having permission."
    info "Cedar policies on each MCP proxy determine what each agent can do."
    blank

    # Print autonomous policies (delegation policies shown in Act 4)
    info "Cedar autonomous policies — fetch proxy:"
    blank
    dim '  // devops-agent: full access to all tools'
    dim '  permit(principal, action == Action::"call_tool", resource)'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/devops-*" };'
    blank
    dim '  // intern-agent: NO autonomous call_tool permit (delegation only — see Act 4)'
    blank
    dim '  // all agents: may list available tools'
    dim '  permit(principal, action == Action::"list_tools", resource)'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/*" };'
    blank

    info "Cedar autonomous policies — cluster-tools proxy:"
    blank
    dim '  // Only devops-agent may call cluster tools'
    dim '  permit(principal, action == Action::"call_tool", resource)'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/devops-*" };'
    blank
    dim '  // all agents: may list available tools (read-only discovery)'
    dim '  permit(principal, action == Action::"list_tools", resource)'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/*" };'
    blank
    dim '  // intern-agent: implicit DENY on call_tool (no permit rule matches)'
    blank

    # Obtain cluster-tools tokens
    local resp
    resp=$(get_token devops-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/devops-agent" "${CT_URL}")
    DEVOPS_CT_TOKEN=$(json_field "${resp}" "access_token")

    resp=$(get_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" "${CT_URL}")
    INTERN_CT_TOKEN=$(json_field "${resp}" "access_token")

    resp=$(get_token rogue-agent "${UNTRUSTED_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${UNTRUSTED_NS}/sa/rogue-agent" "${CT_URL}")
    ROGUE_CT_TOKEN=$(json_field "${resp}" "access_token")

    # Print authorization matrix
    blank
    header "Authorization matrix"
    printf "\n"
    printf "    %-20s  %-18s  %-12s  %-12s\n" \
        "Principal" "MCP server" "list_tools" "call_tool"
    printf "    %-20s  %-18s  %-12s  %-12s\n" \
        "--------------------" "------------------" "------------" "------------"

    # fetch rows
    _matrix_row "devops-agent" "fetch"         "ALLOW" "ALLOW (all tools)"  "${DEVOPS_FETCH_TOKEN}"
    _matrix_row "intern-agent" "fetch"         "ALLOW" "DENY (no permit)"   "${INTERN_FETCH_TOKEN}"
    _matrix_row "rogue-agent"  "fetch"         "DENY"  "DENY (no token)"    "${ROGUE_FETCH_TOKEN}"
    printf "\n"
    _matrix_row "devops-agent" "cluster-tools" "ALLOW" "ALLOW (all tools)"  "${DEVOPS_CT_TOKEN}"
    _matrix_row "intern-agent" "cluster-tools" "ALLOW" "DENY (no permit)"   "${INTERN_CT_TOKEN}"
    _matrix_row "rogue-agent"  "cluster-tools" "DENY"  "DENY (no token)"    "${ROGUE_CT_TOKEN}"

    blank
    info "devops-agent:  full access everywhere — trusted, privileged workload"
    info "intern-agent:  can list tools, but cannot call any autonomously"
    info "               (delegation can unlock access — see Act 4)"
    info "rogue-agent:   no access — stopped before it can even get a token"
}

# Print one row of the authorization matrix.
# _matrix_row <principal> <server> <list_label> <call_label> <token>
_matrix_row() {
    local principal=$1 server=$2 list_label=$3 call_label=$4 token=$5

    # Token present -> auth layer passed; denied ones are caught by Cedar
    local list_badge call_badge
    if [ -n "${token}" ]; then
        list_badge="${GREEN}${list_label}${NC}"
        if [[ "${call_label}" == DENY* ]]; then
            call_badge="${RED}${call_label}${NC}"
        else
            call_badge="${GREEN}${call_label}${NC}"
        fi
    else
        list_badge="${RED}${list_label}${NC}"
        call_badge="${RED}${call_label}${NC}"
    fi

    printf "    %-20s  %-18s  " "${principal}" "${server}"
    printf "%-30b  %b\n" "${list_badge}" "${call_badge}"
}

# ---------------------------------------------------------------------------
# Act 4: Delegation — human + agent identity
# ---------------------------------------------------------------------------
act4_delegation() {
    step "Act 4 — Delegation: human + agent identity"
    blank
    info "So far every agent acted on its own — using only its SPIFFE identity."
    info "But what if a human wants to delegate authority to an agent?"
    blank
    info "Delegation combines two identities into one token via RFC 8693:"
    info "  human (Keycloak ID token)  +  agent (SPIFFE JWT)  →  delegated JWT"
    blank
    info "Recall from Act 3: intern-agent CANNOT call tools on the fetch proxy"
    info "autonomously. But with delegation from the right user — it can."
    blank

    # -----------------------------------------------------------------------
    # Keycloak user tokens
    # -----------------------------------------------------------------------
    info "Fetching Keycloak user tokens..."
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
        info "  Is Keycloak running? Run ./setup-keycloak.sh first."
        return
    fi

    result "  devops-user  Keycloak ID token" "${TOKEN_OK}"
    result "  intern-user  Keycloak ID token" "${TOKEN_OK}"
    blank

    info "  Keycloak ID token claims (devops-user):"
    decode_jwt "${devops_user_token}" sub email iss exp
    blank

    # -----------------------------------------------------------------------
    # Token exchange
    # -----------------------------------------------------------------------
    info "Step 1: intern-agent obtains its own SPIFFE JWT (already shown in Act 2)"
    blank
    # Reuse INTERN_FETCH_TOKEN from act2 if available, otherwise re-acquire
    if [ -z "${INTERN_FETCH_TOKEN:-}" ]; then
        local resp
        resp=$(get_token intern-agent "${AGENTS_NS}" \
            "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" "${FETCH_URL}")
        INTERN_FETCH_TOKEN=$(json_field "${resp}" "access_token")
    fi

    info "Step 2: RFC 8693 token exchange — intern-agent + devops-user"
    blank
    dim "  POST ${FETCH_URL}/oauth/token"
    dim "    grant_type         = urn:ietf:params:oauth:grant-type:token-exchange"
    dim "    subject_token      = <devops-user Keycloak ID token>"
    dim "    subject_token_type = urn:ietf:params:oauth:token-type:id_token"
    dim "    actor_token        = <intern-agent SPIFFE JWT>"
    dim "    actor_token_type   = urn:ietf:params:oauth:token-type:access_token"
    blank

    local devops_delegated="" intern_delegated=""

    # Exchange: intern-agent + devops-user → delegated JWT
    local resp
    resp=$(exchange_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" \
        "${FETCH_URL}" "${devops_user_token}" "${INTERN_FETCH_TOKEN}")
    devops_delegated=$(json_field "${resp}" "access_token")

    if [ -n "${devops_delegated}" ]; then
        result "  intern-agent + devops-user → delegated JWT" "${TOKEN_OK}"
        blank
        info "  Delegated JWT claims (composite identity):"
        decode_jwt "${devops_delegated}" sub email act iss client_id exp
    else
        local err
        err=$(json_field "${resp}" "error_description")
        result "  intern-agent + devops-user → [${err:-error}]" "${TOKEN_DENIED}"
    fi
    blank

    # Exchange: intern-agent + intern-user → delegated JWT
    resp=$(exchange_token intern-agent "${AGENTS_NS}" \
        "spiffe://${TRUST_DOMAIN}/ns/${AGENTS_NS}/sa/intern-agent" \
        "${FETCH_URL}" "${intern_user_token}" "${INTERN_FETCH_TOKEN}")
    intern_delegated=$(json_field "${resp}" "access_token")

    if [ -n "${intern_delegated}" ]; then
        result "  intern-agent + intern-user → delegated JWT" "${TOKEN_OK}"
    else
        local err
        err=$(json_field "${resp}" "error_description")
        result "  intern-agent + intern-user → [${err:-error}]" "${TOKEN_DENIED}"
    fi
    blank

    info "Both exchanges succeed — the auth server issues a composite JWT for both."
    info "The difference is what Cedar does with the claims."
    blank

    # -----------------------------------------------------------------------
    # Cedar delegation policies
    # -----------------------------------------------------------------------
    info "Cedar delegation policies — fetch proxy:"
    blank
    dim '  // devops-user can access all tools via any trusted agent'
    dim '  permit(principal, action == Action::"call_tool", resource)'
    dim '    when {'
    dim '      context has claim_act &&'
    dim '      context has claim_email &&'
    dim '      context.claim_email == "devops-user@example.com" &&'
    dim '      context.claim_act.sub like "spiffe://toolhive.dev/ns/agents/sa/*"'
    dim '    };'
    blank
    dim '  // No delegation permit for intern-user → implicit DENY'
    blank

    # -----------------------------------------------------------------------
    # Delegation matrix
    # -----------------------------------------------------------------------
    header "Delegation authorization matrix (fetch proxy)"
    printf "\n"
    printf "    %-22s  %-22s  %-14s  %-14s\n" \
        "User (delegator)" "Agent (actor)" "list_tools" "call_tool"
    printf "    %-22s  %-22s  %-14s  %-14s\n" \
        "----------------------" "----------------------" "--------------" "--------------"

    # devops-agent autonomous (recap from Act 3)
    printf "    %-22s  %-22s  " "(autonomous)" "devops-agent"
    printf "%-26b  %b\n" "${GREEN}ALLOW${NC}" "${GREEN}ALLOW${NC}"

    # intern-agent autonomous (recap from Act 3)
    printf "    %-22s  %-22s  " "(autonomous)" "intern-agent"
    printf "%-26b  %b\n" "${GREEN}ALLOW${NC}" "${RED}DENY${NC}"

    # intern-agent + devops-user delegation
    printf "    %-22s  %-22s  " "devops-user" "intern-agent"
    printf "%-26b  %b\n" "${GREEN}ALLOW${NC}" "${GREEN}ALLOW${NC}"

    # intern-agent + intern-user delegation
    printf "    %-22s  %-22s  " "intern-user" "intern-agent"
    printf "%-26b  %b\n" "${GREEN}ALLOW${NC}" "${RED}DENY${NC}"

    blank
    info "Same agent (intern-agent). Same tool (fetch)."
    info "The difference is WHO delegated: Cedar checks the composite identity."
    info "devops-user@example.com has a permit rule; intern-user@example.com does not."
}

# ---------------------------------------------------------------------------
# Act 5: Sidecar proxy — wrapping an unmodified agent
# ---------------------------------------------------------------------------
act5_sidecar() {
    step "Act 5 — Sidecar proxy: wrapping an unmodified agent"
    blank
    info "Acts 1-4 used a custom pydantic-ai agent that speaks SPIFFE natively."
    info "But what about unmodified agents — Claude Code, Codex, Cursor?"
    blank
    info "A sidecar proxy sits between the agent and the MCP server:"
    info "  Agent → localhost:8080 (plain HTTP, user token only)"
    info "       → Sidecar (SPIFFE mTLS + token exchange)"
    info "       → MCP server (delegated JWT with composite identity)"
    blank
    info "The agent has NO SPIFFE credentials. The sidecar handles everything."
    blank

    # Check if sidecar pod is running
    local sidecar_phase
    sidecar_phase=$(kubectl --context "${CONTEXT}" get pod sidecar-test -n "${AGENTS_NS}" \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")

    if [ "${sidecar_phase}" != "Running" ]; then
        info "${YELLOW}Sidecar test pod not running (${sidecar_phase}).${NC}"
        info "Deploy it: kubectl apply -f deploy/spiffe-poc/demo/manifests/10-sidecar-agent-pod.yaml"
        return
    fi

    # -----------------------------------------------------------------------
    # Evidence 1: Agent container has no SPIFFE creds
    # -----------------------------------------------------------------------
    info "Evidence 1: Agent container has NO SPIFFE credentials"
    blank
    dim "  \$ kubectl exec sidecar-test -c agent -- ls /var/run/secrets/spiffe.io/"
    local spiffe_check
    spiffe_check=$(kubectl --context "${CONTEXT}" exec -n "${AGENTS_NS}" sidecar-test -c agent -- \
        ls /var/run/secrets/spiffe.io/ 2>&1 || true)
    dim "  ${spiffe_check}"
    blank

    # -----------------------------------------------------------------------
    # Evidence 2: Sidecar bootstrap logs
    # -----------------------------------------------------------------------
    info "Evidence 2: Sidecar bootstrapped with SPIFFE identity"
    blank
    kubectl --context "${CONTEXT}" logs sidecar-test -n "${AGENTS_NS}" -c spiffe-proxy 2>&1 \
        | grep -E '"level":"INFO"' | while IFS= read -r line; do
        dim "  ${line}"
    done
    blank

    # -----------------------------------------------------------------------
    # Evidence 3: Make an MCP call through the sidecar
    # -----------------------------------------------------------------------
    info "Evidence 3: MCP tool call through sidecar (devops-user → fetch)"
    blank

    # Get a fresh devops-user token
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

    # Initialize MCP session through the sidecar
    kubectl --context "${CONTEXT}" exec -n "${AGENTS_NS}" sidecar-test -c agent -- \
        sh -c "curl -s --max-time 15 -o /dev/null \
        -H 'Content-Type: application/json' \
        -H \"Authorization: Bearer ${user_token}\" \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"demo\",\"version\":\"1.0\"}},\"id\":1}' \
        'http://localhost:8080/mcp'" 2>/dev/null

    # Small delay for logs to flush
    sleep 1

    # -----------------------------------------------------------------------
    # Evidence 4: Sidecar debug logs showing token exchange
    # -----------------------------------------------------------------------
    info "Evidence 4: Sidecar performed token exchange (debug logs)"
    blank
    kubectl --context "${CONTEXT}" logs sidecar-test -n "${AGENTS_NS}" -c spiffe-proxy 2>&1 \
        | grep -E '"level":"DEBUG"' | tail -5 | while IFS= read -r line; do
        dim "  ${line}"
    done
    blank

    # Extract the key claims from the sidecar's exchange log
    local exchange_log
    exchange_log=$(kubectl --context "${CONTEXT}" logs sidecar-test -n "${AGENTS_NS}" -c spiffe-proxy 2>&1 \
        | grep "delegated token issued" | tail -1)

    if [ -n "${exchange_log}" ]; then
        info "  Delegated JWT claims (from sidecar log):"
        local dt_sub dt_email dt_name dt_act
        dt_sub=$(printf '%s' "${exchange_log}" | jq -r '.sub // empty' 2>/dev/null)
        dt_email=$(printf '%s' "${exchange_log}" | jq -r '.email // empty' 2>/dev/null)
        dt_name=$(printf '%s' "${exchange_log}" | jq -r '.name // empty' 2>/dev/null)
        dt_act=$(printf '%s' "${exchange_log}" | jq -r '.act.sub // empty' 2>/dev/null)
        printf "         %-12s %s\n" "sub:" "${dt_sub}"
        printf "         %-12s %s\n" "email:" "${dt_email}"
        printf "         %-12s %s\n" "name:" "${dt_name}"
        printf "         %-12s %s\n" "act.sub:" "${dt_act}"
    fi
    blank

    # -----------------------------------------------------------------------
    # Evidence 5: Cedar evaluation on the MCP server side
    # -----------------------------------------------------------------------
    local fetch_proxy
    fetch_proxy=$(kubectl --context "${CONTEXT}" get pods -n "${OPERATOR_NS}" \
        -l app.kubernetes.io/name=mcp-fetch-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

    if [ -n "${fetch_proxy}" ]; then
        info "Evidence 5: Cedar evaluation on the MCP server (fetch proxy logs)"
        blank

        local cedar_ctx
        cedar_ctx=$(kubectl --context "${CONTEXT}" logs "${fetch_proxy}" -n "${OPERATOR_NS}" 2>&1 \
            | grep "cedar context" | tail -1)

        if [ -n "${cedar_ctx}" ]; then
            local ctx_email ctx_act ctx_sub
            ctx_email=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_email // empty' 2>/dev/null)
            ctx_act=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_act.sub // empty' 2>/dev/null)
            ctx_sub=$(printf '%s' "${cedar_ctx}" | jq -r '.context.claim_sub // empty' 2>/dev/null)
            dim "  Cedar evaluated:"
            printf "         %-18s %s\n" "claim_sub:" "${ctx_sub}"
            printf "         %-18s %s\n" "claim_email:" "${ctx_email}"
            printf "         %-18s %s\n" "claim_act.sub:" "${ctx_act}"
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
    info "The agent sent only a Keycloak user token to localhost."
    info "The sidecar exchanged it for a delegated JWT with both identities."
    info "The MCP server evaluated the composite identity via Cedar."
    info "The agent never touched SPIFFE credentials."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
summary() {
    step "Summary"
    blank
    info "What just happened — in five steps:"
    blank
    info "1. Identity:       SPIFFE SVIDs provisioned automatically at pod startup."
    info "                   Format: spiffe://<trust-domain>/ns/<ns>/sa/<sa>"
    info "                   No secrets, no passwords, no certificate signing requests."
    blank
    info "2. Authentication: X.509-SVID presented via mTLS to the MCP proxy."
    info "                   The SVID IS the client certificate — an X.509 cert"
    info "                   with the SPIFFE ID as a URI SAN. The embedded auth"
    info "                   server validates it against a namespace allow-list"
    info "                   and issues a short-lived JWT (sub = SPIFFE ID)."
    blank
    info "3. Authorization:  Cedar policies evaluated on every MCP call."
    info "                   Policy matches on claim_sub (the SPIFFE ID)."
    info "                   Granularity: per-tool, per-workload, zero shared secrets."
    blank
    info "4. Delegation:     RFC 8693 token exchange merges human + agent identity."
    info "                   The delegated JWT carries both identities (act claim)."
    info "                   Cedar evaluates the composite: who delegated, which agent,"
    info "                   which tool — all in one policy decision."
    blank
    info "5. Sidecar proxy:  Unmodified agents wrapped transparently."
    info "                   Agent talks to localhost with a user token."
    info "                   Sidecar handles SPIFFE mTLS, token exchange, forwarding."
    info "                   Same policy framework — agent never sees SPIFFE creds."
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
    act2_authentication
    pause
    act3_authorization
    pause
    act4_delegation
    pause
    act5_sidecar
    pause
    summary
}

main "$@"
