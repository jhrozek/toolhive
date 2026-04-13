#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the pydantic-ai SPIFFE agent image and load it into the kind cluster.
#
# Usage: ./build-agent.sh [--no-load]
#
# Options:
#   --no-load    Build the image but don't load it into kind

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$SCRIPT_DIR/agent"
IMAGE_NAME="spiffe-mcp-agent"
IMAGE_TAG="latest"
KIND_CLUSTER="${KIND_CLUSTER:-toolhive}"

echo "=== Building $IMAGE_NAME:$IMAGE_TAG ==="
docker build -t "$IMAGE_NAME:$IMAGE_TAG" "$AGENT_DIR"

if [ "$1" = "--no-load" ]; then
    echo "Skipping kind load (--no-load)"
    exit 0
fi

echo ""
echo "=== Loading into kind cluster '$KIND_CLUSTER' ==="
kind load docker-image "$IMAGE_NAME:$IMAGE_TAG" --name "$KIND_CLUSTER"

echo ""
echo "=== Done ==="
echo "Image: $IMAGE_NAME:$IMAGE_TAG"
echo "Run demo pods: kubectl apply -f $AGENT_DIR/manifests/"
