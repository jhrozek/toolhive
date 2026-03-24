#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 The ToolHive Authors.
#
# Sets up the SPIFFE PoC infrastructure from scratch on a local kind cluster.
# Idempotent: safe to re-run (the kind cluster is deleted and recreated each
# time to guarantee a clean slate).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"

CLUSTER_NAME="${CLUSTER_NAME:-spiffe-poc}"
TRUST_DOMAIN="${TRUST_DOMAIN:-toolhive.dev}"

CERT_MANAGER_VERSION="v1.17.1"
APPROVER_POLICY_VERSION="v0.18.0"
CSI_DRIVER_SPIFFE_VERSION="v0.9.1"

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m    OK: %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
for cmd in kind kubectl helm; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found in PATH"
done

# ---------------------------------------------------------------------------
# Kind cluster
# ---------------------------------------------------------------------------
log "Recreating kind cluster '${CLUSTER_NAME}'"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  kind delete cluster --name "${CLUSTER_NAME}"
fi
kind create cluster --name "${CLUSTER_NAME}"
kubectl cluster-info --context "kind-${CLUSTER_NAME}"

# ---------------------------------------------------------------------------
# cert-manager (default approver disabled so approver-policy can take over)
# ---------------------------------------------------------------------------
log "Adding Jetstack Helm repo"
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update

log "Installing cert-manager ${CERT_MANAGER_VERSION}"
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version "${CERT_MANAGER_VERSION}" \
  --set crds.enabled=true \
  --set "extraArgs[0]=--controllers=*\,-certificaterequests-approver"

log "Waiting for cert-manager pods"
kubectl rollout status deployment/cert-manager           -n cert-manager --timeout=120s
kubectl rollout status deployment/cert-manager-cainjector -n cert-manager --timeout=120s
kubectl rollout status deployment/cert-manager-webhook    -n cert-manager --timeout=120s

# ---------------------------------------------------------------------------
# CA chain
# ---------------------------------------------------------------------------
log "Applying CA chain manifests"
kubectl apply -f "${MANIFESTS_DIR}/01-selfsigned-issuer.yaml"
kubectl apply -f "${MANIFESTS_DIR}/02-root-ca-certificate.yaml"

# The default cert-manager approver is disabled (required for csi-driver-spiffe)
# and approver-policy is not yet installed, so we must manually approve the
# bootstrap CertificateRequest for the root CA.
log "Waiting for root CA CertificateRequest to appear"
for i in $(seq 1 30); do
  CR_NAME=$(kubectl get certificaterequest -n cert-manager -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "$CR_NAME" ] && break
  sleep 2
done
[ -z "$CR_NAME" ] && die "Root CA CertificateRequest never appeared"

log "Manually approving bootstrap CertificateRequest '${CR_NAME}'"
# Note: `kubectl certificate approve` targets Kubernetes CSRs, not cert-manager
# CertificateRequests. We patch the status subresource directly.
kubectl patch certificaterequest "$CR_NAME" -n cert-manager \
  --type=merge --subresource=status \
  -p '{"status":{"conditions":[{"type":"Approved","status":"True","reason":"ManualBootstrap","message":"Bootstrap root CA approval","lastTransitionTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}]}}'

log "Waiting for root CA certificate to be ready"
kubectl wait --for=condition=Ready certificate/spiffe-root-ca \
  -n cert-manager --timeout=60s

kubectl apply -f "${MANIFESTS_DIR}/03-ca-clusterissuer.yaml"

log "Waiting for spiffe-ca-issuer to be ready"
kubectl wait --for=condition=Ready clusterissuer/spiffe-ca-issuer --timeout=60s

# ---------------------------------------------------------------------------
# approver-policy + RBAC
# ---------------------------------------------------------------------------
log "Installing approver-policy ${APPROVER_POLICY_VERSION}"
helm upgrade --install approver-policy jetstack/cert-manager-approver-policy \
  --namespace cert-manager \
  --version "${APPROVER_POLICY_VERSION}" \
  --set "app.approveSignerNames={issuers.cert-manager.io/*,clusterissuers.cert-manager.io/*}"

log "Waiting for approver-policy deployment"
kubectl rollout status deployment/cert-manager-approver-policy \
  -n cert-manager --timeout=120s

log "Granting cert-manager-controller RBAC for CertificateRequestPolicy"
kubectl apply -f - <<'RBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-policy:use-all
rules:
  - apiGroups: ["policy.cert-manager.io"]
    resources: ["certificaterequestpolicies"]
    verbs: ["use"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-policy:use-all
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-policy:use-all
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
RBAC

log "Applying CertificateRequestPolicy"
kubectl apply -f "${MANIFESTS_DIR}/04-server-cert-policy.yaml"

log "Waiting for CertificateRequestPolicy to be ready"
kubectl wait --for=condition=Ready certificaterequestpolicy/allow-server-certs --timeout=60s

# ---------------------------------------------------------------------------
# csi-driver-spiffe (with sourceCABundle so ca.crt lands in the volume)
# ---------------------------------------------------------------------------
log "Installing csi-driver-spiffe ${CSI_DRIVER_SPIFFE_VERSION}"
helm upgrade --install csi-driver-spiffe jetstack/cert-manager-csi-driver-spiffe \
  --namespace cert-manager \
  --version "${CSI_DRIVER_SPIFFE_VERSION}" \
  --set "app.trustDomain=${TRUST_DOMAIN}" \
  --set "app.issuer.name=spiffe-ca-issuer" \
  --set "app.issuer.kind=ClusterIssuer" \
  --set "app.issuer.group=cert-manager.io" \
  --set "app.driver.sourceCABundle=/var/run/secrets/spiffe-root-ca/ca.crt" \
  --set "app.driver.volumes[0].name=spiffe-root-ca" \
  --set "app.driver.volumes[0].secret.secretName=spiffe-root-ca-secret" \
  --set "app.driver.volumeMounts[0].name=spiffe-root-ca" \
  --set "app.driver.volumeMounts[0].mountPath=/var/run/secrets/spiffe-root-ca" \
  --set "app.driver.volumeMounts[0].readOnly=true"

log "Waiting for csi-driver-spiffe DaemonSet"
kubectl rollout status daemonset/cert-manager-csi-driver-spiffe-driver \
  -n cert-manager --timeout=120s

# ---------------------------------------------------------------------------
# RBAC for CSI driver — the CSI driver creates CertificateRequests using
# the pod's ServiceAccount identity, so each SA needs permission.
# ---------------------------------------------------------------------------
log "Creating RBAC for CSI driver CertificateRequest creation"
kubectl apply -f - <<'CSRBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: spiffe-csi-certificaterequest-creator
rules:
  - apiGroups: ["cert-manager.io"]
    resources: ["certificaterequests"]
    verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spiffe-csi-certificaterequest-creator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: spiffe-csi-certificaterequest-creator
subjects:
  - kind: Group
    name: system:serviceaccounts
    apiGroup: rbac.authorization.k8s.io
CSRBAC

# ---------------------------------------------------------------------------
# Test pod
# ---------------------------------------------------------------------------
log "Deploying test pod"
kubectl apply -f "${MANIFESTS_DIR}/05-test-pod.yaml"
kubectl wait --for=condition=Ready pod/spiffe-test --timeout=120s

# ---------------------------------------------------------------------------
# Verify SVID + ca.crt
# ---------------------------------------------------------------------------
log "Verifying SPIFFE volume contents"
kubectl exec spiffe-test -- ls -la /var/run/secrets/spiffe.io/

if kubectl exec spiffe-test -- ls /var/run/secrets/spiffe.io/ca.crt >/dev/null 2>&1; then
  ok "ca.crt is present in the SPIFFE volume"
else
  die "ca.crt is MISSING from the SPIFFE volume — check csi-driver-spiffe sourceCABundle settings"
fi

# ---------------------------------------------------------------------------
# toolhive-system namespace + authserver certificate
# ---------------------------------------------------------------------------
log "Creating toolhive-system namespace"
kubectl create namespace toolhive-system --dry-run=client -o yaml | kubectl apply -f -

log "Applying authserver TLS certificate"
kubectl apply -f "${MANIFESTS_DIR}/06-authserver-cert.yaml"
kubectl wait --for=condition=Ready certificate/authserver-tls \
  -n toolhive-system --timeout=60s

# ---------------------------------------------------------------------------
# CA bundle ConfigMap
# ---------------------------------------------------------------------------
log "Creating CA bundle ConfigMap in toolhive-system"
CA_DATA=$(kubectl get secret spiffe-root-ca-secret -n cert-manager \
  -o jsonpath='{.data.ca\.crt}' | base64 -d)
kubectl create configmap spiffe-ca-bundle \
  --namespace toolhive-system \
  --from-literal=ca.crt="${CA_DATA}" \
  --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n\033[1;32m========================================\033[0m\n'
printf '\033[1;32m SPIFFE PoC setup complete\033[0m\n'
printf '\033[1;32m========================================\033[0m\n'
printf '  Cluster:       kind-%s\n' "${CLUSTER_NAME}"
printf '  Trust domain:  %s\n' "${TRUST_DOMAIN}"
printf '  CA issuer:     spiffe-ca-issuer (ClusterIssuer)\n'
printf '\n'
printf '  Certificates:\n'
kubectl get certificates -A
printf '\n'
printf '  SPIFFE test pod volume:\n'
kubectl exec spiffe-test -- ls -la /var/run/secrets/spiffe.io/
printf '\n'
printf '  To inspect the SVID:\n'
printf '    kubectl exec spiffe-test -- cat /var/run/secrets/spiffe.io/tls.crt | openssl x509 -text -noout\n'
printf '\n'
