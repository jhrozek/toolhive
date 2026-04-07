#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# mcp-call.sh — Minimal MCP client for demo recordings.
# Runs inside an agent pod. Authenticates via SPIFFE mTLS,
# initializes an MCP session, and calls a tool.
#
# Usage: mcp-call.sh <proxy-url> <tool-name> '<arguments-json>'
# Example: mcp-call.sh https://mcp-fetch-proxy...:8080 fetch '{"url":"https://example.com"}'

set -e

PROXY="$1"
TOOL="$2"
ARGS="$3"

CERT=/var/run/secrets/spiffe.io/tls.crt
KEY=/var/run/secrets/spiffe.io/tls.key
CA=/var/run/secrets/spiffe.io/ca.crt

# Extract SPIFFE ID from certificate
CLIENT_ID=$(openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null \
  | grep -o 'URI:spiffe://[^ ,]*' | sed 's/URI://')

# Step 1: Get OAuth token via mTLS client_credentials
TOKEN=$(curl -sk --cert "$CERT" --key "$KEY" --cacert "$CA" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${CLIENT_ID}&resource=${PROXY}" \
  "${PROXY}/oauth/token" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

AUTH="-H \"Authorization: Bearer $TOKEN\""
HDR="-H \"Content-Type: application/json\""

# Step 2: Initialize MCP session
SESSION=$(curl -sk --cacert "$CA" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -D - -o /dev/null \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}},"id":1}' \
  "${PROXY}/mcp" 2>/dev/null | grep -i mcp-session-id | tr -d '\r' | cut -d: -f2 | tr -d ' ')

# Step 3: Send initialized notification
curl -sk --cacert "$CA" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "${PROXY}/mcp" > /dev/null 2>&1

# Step 4: Call the tool
curl -sk --cacert "$CA" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"${TOOL}\",\"arguments\":${ARGS}},\"id\":2}" \
  "${PROXY}/mcp"
