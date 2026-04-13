#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the four-scenario delegation demo.
#
# Scenarios:
#   1. devops-agent autonomous     → PERMIT (SPIFFE ID matches Cedar policy)
#   2. intern-agent autonomous     → DENY   (no Cedar permit for intern on fetch)
#   3. intern + devops-user token  → PERMIT (delegation: devops-user email grants access)
#   4. intern + intern-user token  → DENY   (no Cedar permit for intern-user email)
#
# Prerequisites:
#   - Cluster running with SPIFFE + Keycloak + MCP servers deployed
#   - Agent image built: ./build-agent.sh
#   - Keycloak set up: ./setup-keycloak.sh
#   - LLM API secret created (see agent/manifests/llm-api-secret.yaml.template)
#   - Agent ConfigMap applied: kubectl apply -f agent/manifests/agent-configmap.yaml

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="agents"
PROXY_URL="https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080"
TASK="You MUST use the fetch tool to retrieve the URL https://httpbin.org/get. Do NOT generate the response from your knowledge - you MUST call the fetch tool. Then summarize the response headers in 2 sentences."

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

run_scenario() {
    local name="$1"
    local sa="$2"
    local description="$3"
    local expected="$4"
    local user_token="${5:-}"
    local subject_token_type="${6:-urn:ietf:params:oauth:token-type:id_token}"

    echo -e "\n${BLUE}=== Scenario: ${description} ===${NC}"
    echo "  Service account: $sa"
    echo "  Expected: $expected"
    if [ -n "$user_token" ]; then
        echo "  Delegation: yes (user token provided)"
    fi
    echo ""

    # Clean up any existing pod
    kubectl delete pod "$name" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null

    # Build pod spec
    local env_block=""
    env_block+="        - name: SPIFFE_PROXY_URL
          value: \"${PROXY_URL}\"
        - name: LLM_MODEL
          valueFrom:
            configMapKeyRef:
              name: agent-config
              key: LLM_MODEL
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: llm-api-key
              key: ANTHROPIC_API_KEY"

    if [ -n "$user_token" ]; then
        env_block+="
        - name: SPIFFE_USER_TOKEN
          value: \"${user_token}\"
        - name: SPIFFE_SUBJECT_TOKEN_TYPE
          value: \"${subject_token_type}\""
    fi

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
spec:
  serviceAccountName: ${sa}
  restartPolicy: Never
  containers:
    - name: agent
      image: spiffe-mcp-agent:latest
      imagePullPolicy: Never
      securityContext:
        runAsUser: 0
      args:
        - "${TASK}"
      env:
${env_block}
      volumeMounts:
        - name: spiffe-certs
          mountPath: /var/run/secrets/spiffe.io
          readOnly: true
  volumes:
    - name: spiffe-certs
      csi:
        driver: spiffe.csi.cert-manager.io
        readOnly: true
        volumeAttributes:
          spiffe.csi.cert-manager.io/certificate-duration: "1h"
EOF

    # Wait for completion (up to 90 seconds)
    echo "Waiting for pod to complete..."
    for i in $(seq 1 90); do
        STATUS=$(kubectl get pod "$name" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
        if [ "$STATUS" = "Succeeded" ] || [ "$STATUS" = "Failed" ]; then
            break
        fi
        sleep 1
    done

    echo ""
    echo "--- Logs ---"
    kubectl logs "$name" -n "$NAMESPACE" 2>&1

    # Report result
    echo ""
    if [ "$STATUS" = "Succeeded" ] && [ "$expected" = "PERMIT" ]; then
        echo -e "${GREEN}✓ PASS: Agent succeeded as expected${NC}"
    elif [ "$STATUS" = "Failed" ] && [ "$expected" = "DENY" ]; then
        echo -e "${GREEN}✓ PASS: Agent was denied as expected${NC}"
    else
        echo -e "${RED}✗ UNEXPECTED: Status=$STATUS, Expected=$expected${NC}"
    fi
}

echo "========================================"
echo "  SPIFFE Delegation Demo — Four Scenarios"
echo "========================================"

# Scenario 1: devops-agent autonomous → PERMIT
run_scenario "demo-s1-devops-auto" "devops-agent" \
    "1. devops-agent autonomous (SPIFFE identity)" "PERMIT"

# Scenario 2: intern-agent autonomous → DENY
run_scenario "demo-s2-intern-auto" "intern-agent" \
    "2. intern-agent autonomous (no Cedar permit for fetch)" "DENY"

# Get Keycloak user tokens for delegation scenarios
echo -e "\n${BLUE}=== Fetching Keycloak user tokens ===${NC}"
kubectl port-forward svc/keycloak-dev-service 8443:8443 -n keycloak &
KC_PF=$!
sleep 5

DEVOPS_USER_TOKEN=$("$SCRIPT_DIR/get-user-token.sh" devops-user devops123 id_token 2>/dev/null)
INTERN_USER_TOKEN=$("$SCRIPT_DIR/get-user-token.sh" intern-user intern123 id_token 2>/dev/null)
kill $KC_PF 2>/dev/null

if [ -z "$DEVOPS_USER_TOKEN" ] || [ -z "$INTERN_USER_TOKEN" ]; then
    echo -e "${RED}Failed to get Keycloak tokens. Is Keycloak running?${NC}"
    exit 1
fi
echo "Got tokens for devops-user and intern-user"

# Scenario 3: intern + devops-user delegation → PERMIT
run_scenario "demo-s3-intern-devops" "intern-agent" \
    "3. intern-agent delegated by devops-user (email grants access)" "PERMIT" \
    "$DEVOPS_USER_TOKEN"

# Scenario 4: intern + intern-user delegation → DENY
run_scenario "demo-s4-intern-intern" "intern-agent" \
    "4. intern-agent delegated by intern-user (no Cedar permit for email)" "DENY" \
    "$INTERN_USER_TOKEN"

echo ""
echo "========================================"
echo "  Demo Complete"
echo "========================================"
echo ""
echo "| # | Scenario                         | Expected | Result |"
echo "|---|----------------------------------|----------|--------|"
for pod in demo-s1-devops-auto demo-s2-intern-auto demo-s3-intern-devops demo-s4-intern-intern; do
    STATUS=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
    echo "| $(echo $pod | sed 's/demo-s//' | cut -c1) | $(printf '%-32s' "$pod") | $(printf '%-8s' "$STATUS") |"
done
