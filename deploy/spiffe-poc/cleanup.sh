#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 The ToolHive Authors.
#
# Tears down the SPIFFE PoC kind cluster.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-spiffe-poc}"

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }

log "Deleting kind cluster '${CLUSTER_NAME}'"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  kind delete cluster --name "${CLUSTER_NAME}"
  printf '\033[1;32m    Cluster deleted.\033[0m\n'
else
  printf '    Cluster "%s" does not exist — nothing to do.\n' "${CLUSTER_NAME}"
fi
