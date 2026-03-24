// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

func TestContextWithSPIFFEID_RoundTrip(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/workload/my-service")
	ctx := ContextWithSPIFFEID(context.Background(), id)

	got, ok := SPIFFEIDFromContext(ctx)
	assert.True(t, ok, "should find SPIFFE ID in context")
	assert.Equal(t, id, got)
}

func TestSPIFFEIDFromContext_Empty(t *testing.T) {
	got, ok := SPIFFEIDFromContext(context.Background())
	assert.False(t, ok, "should not find SPIFFE ID in empty context")
	assert.True(t, got.IsZero(), "returned ID should be zero value")
}
