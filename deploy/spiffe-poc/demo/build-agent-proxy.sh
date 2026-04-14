#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the thv-agent-proxy binary and container image, load into kind.
#
# Usage: ./build-agent-proxy.sh [--no-load]
#
# Options:
#   --no-load    Build the image but don't load it into kind

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/../../.."
IMAGE_NAME="thv-agent-proxy"
IMAGE_TAG="latest"
KIND_CLUSTER="${KIND_CLUSTER:-toolhive}"

echo "=== Building $IMAGE_NAME binary ==="
cd "$REPO_ROOT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/thv-agent-proxy ./cmd/thv-agent-proxy/

echo "=== Building $IMAGE_NAME:$IMAGE_TAG image ==="
# Use a simple Dockerfile inline — static binary on distroless
docker build -t "$IMAGE_NAME:$IMAGE_TAG" -f - "$REPO_ROOT" <<'DOCKERFILE'
FROM cgr.dev/chainguard/static:latest
COPY bin/thv-agent-proxy /thv-agent-proxy
ENTRYPOINT ["/thv-agent-proxy"]
DOCKERFILE

if [ "$1" = "--no-load" ]; then
    echo "Skipping kind load (--no-load)"
    exit 0
fi

echo "=== Loading into kind cluster '$KIND_CLUSTER' ==="
kind load docker-image "$IMAGE_NAME:$IMAGE_TAG" --name "$KIND_CLUSTER"

echo "=== Done ==="
echo "Image: $IMAGE_NAME:$IMAGE_TAG"
