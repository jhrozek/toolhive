# SPIFFE PoC — local kind cluster setup

This directory contains a reproducible setup for a local SPIFFE/X.509 SVID
infrastructure built on top of [kind](https://kind.sigs.k8s.io/),
[cert-manager](https://cert-manager.io/), and
[csi-driver-spiffe](https://github.com/cert-manager/csi-driver-spiffe).

It is used to validate the ToolHive auth-server mTLS transport design described
in `spiffe-poc-plan.md`.

## What gets installed

| Component | Version | Notes |
|---|---|---|
| cert-manager | v1.17.1 | Default approver disabled; approver-policy takes over |
| cert-manager-approver-policy | v0.18.0 | Evaluates CertificateRequestPolicy resources |
| cert-manager-csi-driver-spiffe | v0.9.1 | Mounts SVID + `ca.crt` into pods via CSI |

Cluster resources created:

- `ClusterIssuer/selfsigned-issuer` — bootstraps the root CA
- `Certificate/spiffe-root-ca` (cert-manager ns) — ECDSA P-256 root CA, 10-year validity
- `ClusterIssuer/spiffe-ca-issuer` — signs all workload SVIDs and server certs
- `CertificateRequestPolicy/allow-server-certs` — approves requests via the CA issuer
- `Pod/spiffe-test` (default ns) — busybox pod with SPIFFE CSI volume for smoke testing
- `Certificate/authserver-tls` (toolhive-system ns) — TLS cert for the auth server
- `ConfigMap/spiffe-ca-bundle` (toolhive-system ns) — PEM CA cert for client trust

## Prerequisites

- [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [`kubectl`](https://kubernetes.io/docs/tasks/tools/)
- [`helm`](https://helm.sh/docs/intro/install/) >= 3

## Usage

```bash
# Create everything from scratch (deletes any existing cluster named spiffe-poc)
./deploy/spiffe-poc/setup.sh

# Override the cluster name or trust domain
CLUSTER_NAME=my-test TRUST_DOMAIN=example.dev ./deploy/spiffe-poc/setup.sh

# Tear everything down
./deploy/spiffe-poc/cleanup.sh
```

The setup script is idempotent with respect to all Kubernetes resources (it
uses `kubectl apply` and `--dry-run=client | kubectl apply` everywhere), but it
**deletes and recreates the kind cluster** on each run to guarantee a clean
slate.

## Verifying the SVID after setup

```bash
# List files in the SPIFFE volume — expect tls.crt, tls.key, ca.crt
kubectl exec spiffe-test -- ls -la /var/run/secrets/spiffe.io/

# Inspect the SVID (should contain a spiffe:// URI SAN)
kubectl exec spiffe-test -- cat /var/run/secrets/spiffe.io/tls.crt \
  | openssl x509 -text -noout

# Verify the CA bundle matches the root CA secret
kubectl exec spiffe-test -- cat /var/run/secrets/spiffe.io/ca.crt \
  > /tmp/spiffe-csi-ca.crt
diff \
  <(openssl x509 -in /tmp/spiffe-csi-ca.crt -text -noout) \
  <(kubectl get secret spiffe-root-ca-secret -n cert-manager \
      -o jsonpath='{.data.ca\.crt}' | base64 -d | openssl x509 -text -noout)
```

## Manifests

| File | Purpose |
|---|---|
| `01-selfsigned-issuer.yaml` | Bootstrap ClusterIssuer (self-signed) |
| `02-root-ca-certificate.yaml` | SPIFFE root CA certificate |
| `03-ca-clusterissuer.yaml` | CA-backed ClusterIssuer for workload certs |
| `04-server-cert-policy.yaml` | CertificateRequestPolicy for server certs |
| `05-test-pod.yaml` | Busybox smoke-test pod with SPIFFE CSI volume |
| `06-authserver-cert.yaml` | TLS certificate for the ToolHive auth server |

## Known PoC shortcuts

- **Broad RBAC for CertificateRequest creation.** The setup grants all
  ServiceAccounts (`system:serviceaccounts`) cluster-wide permission to create
  cert-manager CertificateRequests. This is required because csi-driver-spiffe
  creates CRs using the pod's SA identity. For production, scope this to
  specific namespaces/service accounts.
- **Single CertificateRequestPolicy.** One policy covers both server certs and
  (indirectly) SPIFFE SVIDs. In production, split into separate policies with
  tighter constraints (URI SAN allowlists, restricted DNS names).
- **Self-signed root CA.** The CA private key lives in a Kubernetes Secret. For
  production, use an external CA backed by an HSM (Vault, AWS PCA, etc.).
- **Static CA bundle ConfigMap.** The trust bundle is copied once at setup time.
  For production, use cert-manager's trust-manager for automatic distribution
  and rotation.
