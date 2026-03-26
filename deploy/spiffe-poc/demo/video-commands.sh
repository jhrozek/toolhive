#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# SPIFFE PoC -- Video Recording Commands
#
# Copy-paste these commands one at a time during the screen recording.
# This is NOT an automated script. Each block corresponds to a section
# in video-script.md.
#
# Prerequisites:
#   - kind-spiffe-poc cluster running with all demo manifests applied
#   - kubectl, openssl, python3 on PATH

# ============================================================
# PREAMBLE -- run this off-camera before recording starts
# ============================================================
CTX="kind-spiffe-poc"
FETCH="https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080"

# Verify everything is ready
kubectl --context $CTX get pods -n agents
kubectl --context $CTX get pods -n untrusted

# ============================================================
# [0:00-0:10] Opening -- Show the three agent pods
# ============================================================

kubectl --context kind-spiffe-poc get pods -n agents
kubectl --context kind-spiffe-poc get pods -n untrusted

# ============================================================
# [0:10-0:25] Identity -- Show SPIFFE ID from the certificate
# ============================================================

kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep URI

# Expected: URI:spiffe://toolhive.dev/ns/agents/sa/devops-agent

# ============================================================
# [0:25-0:45] Authentication -- Get a token, decode the JWT
# ============================================================

# Step A: Get the token
TOKEN=$(kubectl --context kind-spiffe-poc exec -n agents devops-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/agents/sa/devops-agent&resource=$FETCH" \
  $FETCH/oauth/token \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Step B: Decode the JWT to show sub and aud
echo "$TOKEN" | cut -d. -f2 | python3 -c "
import sys,base64,json
r=sys.stdin.read().strip(); r+='='*((4-len(r)%4)%4)
d=json.loads(base64.urlsafe_b64decode(r))
for k in['sub','aud','exp']:print(f'{k}: {d[k]}')"

# Expected:
#   sub: spiffe://toolhive.dev/ns/agents/sa/devops-agent
#   aud: ['https://mcp-fetch-proxy.toolhive-system.svc.cluster.local:8080']
#   exp: <unix timestamp>

# ============================================================
# [0:45-0:55] Denial -- Rogue agent rejected
# ============================================================

kubectl --context kind-spiffe-poc exec -n untrusted rogue-agent -- \
  curl -sk --cert /var/run/secrets/spiffe.io/tls.crt \
  --key /var/run/secrets/spiffe.io/tls.key \
  --cacert /var/run/secrets/spiffe.io/ca.crt \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=spiffe://toolhive.dev/ns/untrusted/sa/rogue-agent&resource=$FETCH" \
  $FETCH/oauth/token

# Expected:
#   {"error":"unauthorized","error_description":"SPIFFE ID is not authorized to register as a client"}

# ============================================================
# [0:55-1:05] Closing -- Narrate over the denial output
# ============================================================
# No command. Deliver the closing line while the denial is on screen.
