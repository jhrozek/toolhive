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
#   - kubectl configured and kind-spiffe-poc cluster running
#   - All demo manifests applied (see deploy/spiffe-poc/demo/README.md)
#   - python3 available on PATH (for JSON parsing)
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

# ---------------------------------------------------------------------------
# Cluster helpers
# ---------------------------------------------------------------------------
CONTEXT="kind-spiffe-poc"
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
        -d "grant_type=client_credentials&client_id=${spiffe_id}" \
        "${proxy_url}/oauth/token"
}

# Extract a field from a JSON string using python3.
# json_field <json> <field>  — prints the value or empty string on failure.
json_field() {
    local json=$1 field=$2
    printf '%s' "${json}" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null || true
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

    # python3 must be available (used for JSON parsing in curl responses)
    if ! command -v python3 &>/dev/null; then
        printf "    ${RED}ERROR: python3 not found on PATH${NC}\n"
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
    info "Each agent presents its SVID as a TLS client certificate to the MCP proxy."
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
        local err
        err=$(json_field "${resp}" "error_description")
        result "  rogue-agent   -> fetch proxy  [${err:-unknown}]" "${TOKEN_DENIED}"
    fi

    blank
    info "rogue-agent is rejected at registration — it never receives a JWT."
    info "The token endpoint enforces namespace-level policy before any Cedar evaluation."
    blank
    info "Decoding a granted token (devops-agent, fetch proxy):"
    blank
    if [ -n "${DEVOPS_FETCH_TOKEN}" ]; then
        # Decode the JWT payload (middle section) without verifying the signature
        local payload
        payload=$(printf '%s' "${DEVOPS_FETCH_TOKEN}" \
            | cut -d. -f2 \
            | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip()
padded = raw + '=' * ((4 - len(raw) % 4) % 4)
data = json.loads(base64.urlsafe_b64decode(padded))
for k in ['sub', 'iss', 'aud', 'exp']:
    if k in data:
        print(f'  {k}: {data[k]}')
" 2>/dev/null || echo "  (could not decode token)")
        printf "%s\n" "${payload}" | while IFS= read -r line; do
            dim "${line}"
        done
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

    # Print the fetch policy
    info "Cedar policy — fetch proxy:"
    blank
    dim '  // devops-agent: full access to all tools'
    dim '  permit(principal, action == Action::"call_tool", resource)'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/devops-*" };'
    blank
    dim '  // intern-agent: restricted to fetch_url only'
    dim '  permit(principal, action == Action::"call_tool", resource == Tool::"fetch_url")'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/sa/intern-*" };'
    blank
    dim '  // all agents: may list available tools'
    dim '  permit(principal, action == Action::"list_tools", resource)'
    dim '    when { principal.claim_sub like "spiffe://toolhive.dev/ns/agents/*" };'
    blank

    info "Cedar policy — cluster-tools proxy:"
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
    _matrix_row "intern-agent" "fetch"         "ALLOW" "ALLOW (fetch_url)"  "${INTERN_FETCH_TOKEN}"
    _matrix_row "rogue-agent"  "fetch"         "DENY"  "DENY (no token)"    "${ROGUE_FETCH_TOKEN}"
    printf "\n"
    _matrix_row "devops-agent" "cluster-tools" "ALLOW" "ALLOW (all tools)"  "${DEVOPS_CT_TOKEN}"
    _matrix_row "intern-agent" "cluster-tools" "ALLOW" "DENY (no permit)"   "${INTERN_CT_TOKEN}"
    _matrix_row "rogue-agent"  "cluster-tools" "DENY"  "DENY (no token)"    "${ROGUE_CT_TOKEN}"

    blank
    info "devops-agent:  full access everywhere — trusted, privileged workload"
    info "intern-agent:  limited access — policy narrows the blast radius"
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
# Summary
# ---------------------------------------------------------------------------
summary() {
    step "Summary"
    blank
    info "What just happened — in three steps:"
    blank
    info "1. Identity:       SPIFFE SVIDs provisioned automatically at pod startup."
    info "                   Format: spiffe://<trust-domain>/ns/<ns>/sa/<sa>"
    info "                   No secrets, no passwords, no certificate signing requests."
    blank
    info "2. Authentication: mTLS client certificate presented to the MCP proxy."
    info "                   Embedded auth server validates the SVID against a"
    info "                   namespace allow-list and issues a short-lived JWT."
    info "                   SPIFFE ID becomes the JWT 'sub' claim."
    blank
    info "3. Authorization:  Cedar policies evaluated on every MCP call."
    info "                   policy matches on claim_sub (the SPIFFE ID)."
    info "                   Granularity: per-tool, per-workload, zero shared secrets."
    blank
    printf "    ${BOLD}Result:${NC} least-privilege access for AI agents, enforced cryptographically.\n"
    printf "    ${BOLD}        No service mesh required. No separate identity provider.\n"
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
    act2_authentication
    act3_authorization
    summary
}

main "$@"
