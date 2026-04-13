#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Setup Keycloak for the SPIFFE delegation demo.
#
# This script:
#   1. Installs the Keycloak operator (if not present)
#   2. Applies the TLS certificate + Keycloak CR
#   3. Waits for Keycloak to be ready
#   4. Runs the base realm setup (setup-realm.sh)
#   5. Creates demo-specific users (devops-user, intern-user)
#
# Prerequisites:
#   - kind cluster with cert-manager + spiffe-ca-issuer (deploy/spiffe-poc/setup.sh)
#   - kubectl configured for the target cluster
#
# Usage: ./setup-keycloak.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
KEYCLOAK_NS="keycloak"
KEYCLOAK_HOST="keycloak-dev-service.keycloak.svc.cluster.local"
KEYCLOAK_PORT="8443"

echo "=== Step 1: Install Keycloak operator ==="
if kubectl get deployment keycloak-operator -n "$KEYCLOAK_NS" &>/dev/null; then
    echo "Keycloak operator already installed, skipping."
else
    # Use the task if available, otherwise install directly
    if command -v task &>/dev/null && task --list 2>/dev/null | grep -q "keycloak:install-operator"; then
        task keycloak:install-operator
    else
        echo "Installing Keycloak operator v26.3.2..."
        kubectl create namespace "$KEYCLOAK_NS" --dry-run=client -o yaml | kubectl apply -f -
        kubectl apply -f "https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.3.2/kubernetes/keycloaks.k8s.keycloak.org-v1.yml"
        kubectl apply -f "https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.3.2/kubernetes/keycloakrealmimports.k8s.keycloak.org-v1.yml"
        kubectl apply -f "https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.3.2/kubernetes/kubernetes.yml" -n "$KEYCLOAK_NS"
        kubectl rollout status deployment/keycloak-operator -n "$KEYCLOAK_NS" --timeout=120s
    fi
fi

echo ""
echo "=== Step 2: Apply Keycloak CA + TLS cert + Keycloak CR ==="
kubectl apply -f "$SCRIPT_DIR/manifests/09-keycloak.yaml"

echo "Waiting for Keycloak CA certificate to be ready..."
kubectl wait certificate/keycloak-ca -n "$KEYCLOAK_NS" --for=condition=Ready --timeout=60s

echo "Waiting for Keycloak TLS certificate to be ready..."
kubectl wait certificate/keycloak-tls -n "$KEYCLOAK_NS" --for=condition=Ready --timeout=60s

echo "Distributing Keycloak CA to toolhive-system namespace..."
# Extract the Keycloak CA cert from the CA secret and create a ConfigMap
# that auth server pods can mount for OIDC discovery/JWKS TLS verification.
kubectl get secret keycloak-ca-secret -n "$KEYCLOAK_NS" \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/keycloak-ca.crt
kubectl create configmap keycloak-ca-bundle \
  --from-file=ca.crt=/tmp/keycloak-ca.crt \
  -n toolhive-system --dry-run=client -o yaml | kubectl apply -f -
rm -f /tmp/keycloak-ca.crt

echo "Waiting for Keycloak to be ready..."
kubectl wait keycloak/keycloak-dev -n "$KEYCLOAK_NS" --for=condition=Ready --timeout=300s

echo ""
echo "=== Step 3: Setup base realm ==="
# Port-forward to reach Keycloak from the host.
# The setup-realm.sh script expects http://localhost:8080 by default,
# but we're running HTTPS on 8443. We'll port-forward 8443 and use
# a wrapper that calls curl with --cacert.
echo "Starting port-forward to Keycloak..."
kubectl port-forward "service/keycloak-dev-service" "8443:8443" -n "$KEYCLOAK_NS" &
PF_PID=$!
trap "kill $PF_PID 2>/dev/null || true" EXIT

# Wait for port-forward to be ready
for i in $(seq 1 30); do
    if curl -sk "https://localhost:8443/health/ready" &>/dev/null; then
        break
    fi
    sleep 1
done

# Get admin credentials
ADMIN_USER=$(kubectl get secret keycloak-dev-initial-admin -n "$KEYCLOAK_NS" -o jsonpath='{.data.username}' | base64 --decode)
ADMIN_PASS=$(kubectl get secret keycloak-dev-initial-admin -n "$KEYCLOAK_NS" -o jsonpath='{.data.password}' | base64 --decode)

# Get admin token (use -k to skip cert verification for localhost port-forward)
KEYCLOAK_URL="https://localhost:8443"
TOKEN=$(curl -sk -d "client_id=admin-cli" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" \
  -d "grant_type=password" \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" | jq -r '.access_token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to get admin token"
    exit 1
fi

# Run the base realm setup inline (adapted from setup-realm.sh for HTTPS)
echo "Creating toolhive realm..."
curl -sk -X POST "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "toolhive",
    "displayName": "ToolHive Realm",
    "enabled": true,
    "accessTokenLifespan": 3600,
    "ssoSessionMaxLifespan": 72000
  }' || echo "Realm may already exist"

echo "Creating mcp-test-client..."
curl -sk -X POST "$KEYCLOAK_URL/admin/realms/toolhive/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "mcp-test-client",
    "enabled": true,
    "publicClient": false,
    "secret": "mcp-test-client-secret",
    "serviceAccountsEnabled": true,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "redirectUris": ["http://localhost:*", "http://127.0.0.1:*"],
    "webOrigins": ["http://localhost:*", "http://127.0.0.1:*"]
  }' || echo "Client may already exist"

echo ""
echo "=== Step 4: Create demo users ==="

echo "Creating devops-user..."
curl -sk -X POST "$KEYCLOAK_URL/admin/realms/toolhive/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "devops-user",
    "enabled": true,
    "email": "devops-user@example.com",
    "emailVerified": true,
    "firstName": "DevOps",
    "lastName": "User",
    "credentials": [{
      "type": "password",
      "value": "devops123",
      "temporary": false
    }]
  }' || echo "User may already exist"

echo "Creating intern-user..."
curl -sk -X POST "$KEYCLOAK_URL/admin/realms/toolhive/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "intern-user",
    "enabled": true,
    "email": "intern-user@example.com",
    "emailVerified": true,
    "firstName": "Intern",
    "lastName": "User",
    "credentials": [{
      "type": "password",
      "value": "intern123",
      "temporary": false
    }]
  }' || echo "User may already exist"

echo ""
echo "=== Keycloak setup complete ==="
echo ""
echo "Keycloak URL (in-cluster): https://$KEYCLOAK_HOST:$KEYCLOAK_PORT"
echo "OIDC discovery: https://$KEYCLOAK_HOST:$KEYCLOAK_PORT/realms/toolhive/.well-known/openid-configuration"
echo ""
echo "Demo users:"
echo "  devops-user / devops123 (email: devops-user@example.com)"
echo "  intern-user / intern123 (email: intern-user@example.com)"
echo ""
echo "Get a user token:"
echo "  curl -sk -d 'client_id=mcp-test-client' -d 'client_secret=mcp-test-client-secret' \\"
echo "    -d 'username=devops-user' -d 'password=devops123' -d 'grant_type=password' -d 'scope=openid email' \\"
echo "    'https://localhost:8443/realms/toolhive/protocol/openid-connect/token' | jq -r '.id_token'"
