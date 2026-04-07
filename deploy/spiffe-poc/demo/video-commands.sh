#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# SPIFFE PoC -- Semi-Interactive Video Recording Script
#
# Run this script once during recording. It executes each section's
# commands, then pauses for the presenter to narrate before continuing.
# Press Enter to advance to the next section.
#
# Usage:
#   # Off-camera: run the preamble
#   deploy/spiffe-poc/demo/video-commands.sh --setup
#
#   # On-camera: run the demo
#   deploy/spiffe-poc/demo/video-commands.sh
#
# Prerequisites:
#   - kind-spiffe-poc cluster running with all demo manifests applied
#   - kubectl, openssl, jq, jwt (jwt-cli) on PATH
#   - mcp-call.sh in this directory

set -euo pipefail

CTX="kind-spiffe-poc"
FETCH="https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Colors and helpers ---
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
CYAN='\033[36m'
RESET='\033[0m'

section() {
  echo ""
  echo -e "${BOLD}━━━ $1 ━━━${RESET}"
  echo ""
}

# Print a command before running it, like a human typing it
run() {
  echo -e "${GREEN}\$ ${CYAN}$*${RESET}"
  "$@"
  echo ""
}

pause() {
  echo ""
  echo -e "${DIM}[Press Enter to continue]${RESET}"
  read -r
}

# ============================================================
# PREAMBLE (--setup flag)
# ============================================================
if [[ "${1:-}" == "--setup" ]]; then
  echo "Bouncing agent pods (1h cert TTL)..."
  kubectl --context "$CTX" delete pod -n agents --all --ignore-not-found
  kubectl --context "$CTX" delete pod -n untrusted --all --ignore-not-found
  kubectl --context "$CTX" apply -f "${SCRIPT_DIR}/manifests/03-agent-pods.yaml"
  echo "Waiting for pods..."
  sleep 10
  kubectl --context "$CTX" get pods -n agents
  kubectl --context "$CTX" get pods -n untrusted

  echo "Copying mcp-call.sh into agent pods..."
  kubectl --context "$CTX" cp "${SCRIPT_DIR}/mcp-call.sh" agents/devops-agent:/tmp/mcp-call.sh
  kubectl --context "$CTX" cp "${SCRIPT_DIR}/mcp-call.sh" agents/intern-agent:/tmp/mcp-call.sh

  echo ""
  echo "Setup complete. Start recording, then run:"
  echo "  ${SCRIPT_DIR}/video-commands.sh"
  exit 0
fi

# ============================================================
# [0:00-0:10] Opening -- Show MCP servers and agent pods
# ============================================================
section "Opening: Three agents, two MCP servers, zero secrets"

run kubectl --context "$CTX" get mcpserver -n toolhive-system

echo -e "${GREEN}\$ ${CYAN}kubectl get mcpserver fetch -o jsonpath='{.spec.authzConfig.inline.policies}' | jq -r '.[]'${RESET}"
kubectl --context "$CTX" get mcpserver fetch -n toolhive-system \
  -o jsonpath='{.spec.authzConfig.inline.policies}' | jq -r '.[]'

echo -e "${GREEN}\$ ${CYAN}kubectl get mcpserver cluster-tools -o jsonpath='{.spec.authzConfig.inline.policies}' | jq -r '.[]'${RESET}"
kubectl --context "$CTX" get mcpserver cluster-tools -n toolhive-system \
  -o jsonpath='{.spec.authzConfig.inline.policies}' | jq -r '.[]'
echo ""

run kubectl --context "$CTX" get pods -n agents
run kubectl --context "$CTX" get pods -n untrusted

pause

# ============================================================
# [0:10-0:30] Identity -- Show SPIFFE ID from the certificate
# ============================================================
section "Identity: SPIFFE ID from the X.509 certificate"

echo -e "${GREEN}\$ ${CYAN}kubectl exec devops-agent -- cat tls.crt | openssl x509 -noout -ext subjectAltName${RESET}"
kubectl --context "$CTX" exec -n agents devops-agent -- \
  cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep URI

pause

# ============================================================
# [0:30-0:55] Authentication -- Get a token, decode the JWT
# ============================================================
section "Authentication: mTLS client_credentials → JWT"

echo -e "${GREEN}\$ ${CYAN}curl --cert tls.crt --key tls.key -d grant_type=client_credentials .../oauth/token | jq .access_token${RESET}"
TOKEN=$(kubectl --context "$CTX" exec -n agents devops-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/devops-agent&resource=${FETCH}" \
  "${FETCH}/oauth/token" \
  | jq -r .access_token)
echo ""

echo -e "${GREEN}\$ ${CYAN}jwt decode \$TOKEN${RESET}"
jwt decode "$TOKEN"

pause

# ============================================================
# [0:55-1:10] Tool call -- devops-agent calls a tool (succeeds)
# ============================================================
section "Tool call: devops-agent → fetch tool (allowed)"

echo -e "${GREEN}\$ ${CYAN}kubectl exec devops-agent -- sh -x mcp-call.sh \$FETCH fetch '{\"url\":\"https://httpbin.org/get\"}'${RESET}"
kubectl --context "$CTX" exec -n agents devops-agent -- \
  sh -x /tmp/mcp-call.sh \
  "${FETCH}" \
  fetch '{"url":"https://httpbin.org/get","raw":true,"max_length":200}'

pause

# ============================================================
# [1:10-1:25] Cedar denial -- intern-agent blocked on cluster-tools
# ============================================================
CLUSTER_TOOLS="https://mcp-cluster-tools-proxy.toolhive-system.svc.cluster.local:8080"
section "Cedar denial: intern-agent → cluster-tools echo (403)"

echo -e "${GREEN}\$ ${CYAN}kubectl exec intern-agent -- sh mcp-call.sh \$CLUSTER_TOOLS echo '{\"message\":\"hello\"}'${RESET}"
kubectl --context "$CTX" exec -n agents intern-agent -- \
  sh /tmp/mcp-call.sh \
  "${CLUSTER_TOOLS}" \
  echo '{"message":"hello"}' || true

pause

# ============================================================
# [1:25-1:40] Registration denial -- Rogue agent rejected
# ============================================================
section "Registration denial: rogue-agent → no token"

echo -e "${GREEN}\$ ${CYAN}kubectl exec rogue-agent -- curl --cert tls.crt -d grant_type=client_credentials .../oauth/token${RESET}"
kubectl --context "$CTX" exec -n untrusted rogue-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent&resource=${FETCH}" \
  "${FETCH}/oauth/token" || true
echo ""

pause

# ============================================================
# [1:40-1:55] Closing
# ============================================================
section "Three agents. Three outcomes."

echo "  devops-agent  → token ✓  tool call ✓"
echo "  intern-agent  → token ✓  tool call ✗ (Cedar: cluster-tools denied)"
echo "  rogue-agent   → token ✗  (registration policy)"
echo ""
echo "draft-ietf-oauth-spiffe-client-auth on ToolHive."
echo ""
echo "Next:"
echo "  • RFC 8693 delegation — user + agent identity in one token (act claim)"
echo "  • Real agent demo with pydantic-ai calling MCP tools via SPIFFE auth"
echo "  • SPIRE integration for image provenance attestation"
echo ""
