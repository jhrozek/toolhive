#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch a Keycloak user token via ROPC (password grant).
#
# Usage:
#   ./get-user-token.sh <username> <password> [id_token|access_token]
#
# Examples:
#   ./get-user-token.sh devops-user devops123              # returns access_token
#   ./get-user-token.sh devops-user devops123 id_token     # returns id_token
#   ./get-user-token.sh intern-user intern123              # returns access_token
#
# Prerequisites:
#   - Keycloak port-forwarded: kubectl port-forward svc/keycloak-dev-service 8443:8443 -n keycloak
#   - Or run from within the cluster where Keycloak DNS resolves

set -e

USERNAME="${1:?Usage: $0 <username> <password> [id_token|access_token]}"
PASSWORD="${2:?Usage: $0 <username> <password> [id_token|access_token]}"
TOKEN_FIELD="${3:-access_token}"

# Try in-cluster URL first, fall back to localhost port-forward
KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}"

RESPONSE=$(curl -sk \
  -d "client_id=mcp-test-client" \
  -d "client_secret=mcp-test-client-secret" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "grant_type=password" \
  -d "scope=openid email" \
  "$KEYCLOAK_URL/realms/toolhive/protocol/openid-connect/token")

TOKEN=$(echo "$RESPONSE" | jq -r ".$TOKEN_FIELD")

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to get $TOKEN_FIELD" >&2
    echo "$RESPONSE" | jq . >&2
    exit 1
fi

echo "$TOKEN"
