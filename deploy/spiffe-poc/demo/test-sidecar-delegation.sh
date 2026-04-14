#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Integration test for the SPIFFE delegation sidecar proxy.
#
# Tests that an unmodified agent (curl) can make MCP calls through the
# sidecar proxy, which performs SPIFFE bootstrap + RFC 8693 token exchange
# transparently.
#
# Scenarios:
#   A. Agent sends devops-user Bearer token → delegated → Cedar permits → tool call succeeds
#   B. Agent sends intern-user Bearer token → delegated → Cedar denies  → tool call denied
#   C. Agent sends no Bearer token          → sidecar returns 401
#
# Prerequisites:
#   - Cluster running with SPIFFE + Keycloak + MCP servers deployed
#   - Sidecar image built: ./build-agent-proxy.sh
#   - Keycloak set up: ./setup-keycloak.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="agents"
POD_NAME="sidecar-test"
PROXY_LOCAL="http://localhost:8080"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0

report() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}✓ PASS${NC}: $name (got $actual)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC}: $name (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

# Run curl from the agent container (plain HTTP to localhost sidecar)
agent_curl() {
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        curl -s --max-time 15 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo "000"
}

# Run curl and capture body (for session ID extraction)
agent_curl_body() {
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        curl -s --max-time 15 "$@" 2>/dev/null
}

# Run curl and capture headers + body
agent_curl_headers() {
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        curl -s --max-time 15 -D - "$@" 2>/dev/null
}

# Initialize an MCP session and return the session ID
# mcp_init <bearer_token>
mcp_init() {
    local token="$1"
    local auth_args=""
    if [ -n "$token" ]; then
        auth_args="-H \"Authorization: Bearer $token\""
    fi

    # Initialize
    local resp
    resp=$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        sh -c "curl -s --max-time 15 -D /tmp/init_headers -o /tmp/init_body \
        -H 'Content-Type: application/json' \
        $auth_args \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}},\"id\":1}' \
        '$PROXY_LOCAL/mcp' && cat /tmp/init_headers" 2>/dev/null)

    local session_id
    session_id=$(echo "$resp" | grep -i "mcp-session-id" | tr -d '\r' | awk -F': ' '{print $2}')
    echo "$session_id"
}

# Call a tool via MCP JSON-RPC
# mcp_call_tool <bearer_token> <session_id> <tool_name> <args_json>
# Returns HTTP status code
mcp_call_tool() {
    local token="$1" session_id="$2" tool="$3" args="$4"
    local auth_args=""
    if [ -n "$token" ]; then
        auth_args="-H \"Authorization: Bearer $token\""
    fi

    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        sh -c "curl -s --max-time 15 -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        -H 'Mcp-Session-Id: $session_id' \
        $auth_args \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args},\"id\":2}' \
        '$PROXY_LOCAL/mcp'" 2>/dev/null || echo "000"
}

echo "========================================"
echo "  Sidecar Proxy Integration Test"
echo "========================================"

# --- Deploy the sidecar test pod ---
echo -e "\n${BLUE}=== Deploying sidecar test pod ===${NC}"
kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found --wait=true 2>/dev/null
kubectl apply -f "$SCRIPT_DIR/manifests/10-sidecar-agent-pod.yaml"

echo "Waiting for pod to be ready..."
kubectl wait pod "$POD_NAME" -n "$NAMESPACE" --for=condition=Ready --timeout=90s

# Give the sidecar time to bootstrap (client_credentials grant)
sleep 8

# Check sidecar health
echo -e "\n${BLUE}=== Checking sidecar health ===${NC}"
HEALTH_STATUS=$(agent_curl "$PROXY_LOCAL/healthz")
report "Sidecar healthz" "200" "$HEALTH_STATUS"

# --- Get Keycloak user tokens ---
echo -e "\n${BLUE}=== Fetching Keycloak user tokens ===${NC}"
kubectl port-forward svc/keycloak-dev-service 8443:8443 -n keycloak &>/dev/null &
KC_PF=$!
sleep 3

DEVOPS_TOKEN=$("$SCRIPT_DIR/get-user-token.sh" devops-user devops123 id_token 2>/dev/null || true)
INTERN_TOKEN=$("$SCRIPT_DIR/get-user-token.sh" intern-user intern123 id_token 2>/dev/null || true)

kill "$KC_PF" 2>/dev/null || true
wait "$KC_PF" 2>/dev/null || true

if [ -z "$DEVOPS_TOKEN" ] || [ -z "$INTERN_TOKEN" ]; then
    echo -e "${RED}Failed to get Keycloak tokens. Is Keycloak running?${NC}"
    exit 1
fi
echo "Got tokens for devops-user and intern-user"

# --- Scenario A: devops-user delegation → PERMIT ---
echo -e "\n${BLUE}=== Scenario A: devops-user delegation (expect PERMIT) ===${NC}"

SESSION_A=$(mcp_init "$DEVOPS_TOKEN")
if [ -n "$SESSION_A" ]; then
    echo "  Got MCP session: ${SESSION_A:0:20}..."

    # Send initialized notification
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        sh -c "curl -s --max-time 10 -o /dev/null \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer $DEVOPS_TOKEN' \
        -H 'Mcp-Session-Id: $SESSION_A' \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}' \
        '$PROXY_LOCAL/mcp'" 2>/dev/null

    STATUS_A=$(mcp_call_tool "$DEVOPS_TOKEN" "$SESSION_A" "fetch" '{"url":"https://httpbin.org/get","raw":true,"max_length":100}')
    report "devops-user delegation → fetch tool" "200" "$STATUS_A"
else
    echo -e "  ${RED}Failed to initialize MCP session${NC}"
    FAIL=$((FAIL + 1))
fi

# --- Scenario B: intern-user delegation → DENY ---
echo -e "\n${BLUE}=== Scenario B: intern-user delegation (expect DENY) ===${NC}"

SESSION_B=$(mcp_init "$INTERN_TOKEN")
if [ -n "$SESSION_B" ]; then
    echo "  Got MCP session: ${SESSION_B:0:20}..."

    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c agent -- \
        sh -c "curl -s --max-time 10 -o /dev/null \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer $INTERN_TOKEN' \
        -H 'Mcp-Session-Id: $SESSION_B' \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}' \
        '$PROXY_LOCAL/mcp'" 2>/dev/null

    STATUS_B=$(mcp_call_tool "$INTERN_TOKEN" "$SESSION_B" "fetch" '{"url":"https://httpbin.org/get","raw":true,"max_length":100}')
    report "intern-user delegation → fetch tool" "403" "$STATUS_B"
else
    echo -e "  ${RED}Failed to initialize MCP session${NC}"
    FAIL=$((FAIL + 1))
fi

# --- Scenario C: no Bearer token → 401 ---
echo -e "\n${BLUE}=== Scenario C: no Bearer token (expect 401) ===${NC}"
STATUS_C=$(agent_curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}' \
    "$PROXY_LOCAL/mcp")
report "no Bearer token → 401" "401" "$STATUS_C"

# --- Check sidecar logs for errors ---
echo -e "\n${BLUE}=== Sidecar proxy logs ===${NC}"
kubectl logs "$POD_NAME" -n "$NAMESPACE" -c spiffe-proxy --tail=10 2>&1

# --- Summary ---
echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
