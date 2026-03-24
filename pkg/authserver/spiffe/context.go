// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package spiffe provides SPIFFE ID extraction and validation middleware
// for the embedded authorization server.
package spiffe

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type contextKey struct{}

// ContextWithSPIFFEID returns a new context with the SPIFFE ID stored.
func ContextWithSPIFFEID(ctx context.Context, id spiffeid.ID) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// SPIFFEIDFromContext retrieves the SPIFFE ID from the context.
// Returns the zero value and false if not present.
func SPIFFEIDFromContext(ctx context.Context) (spiffeid.ID, bool) {
	id, ok := ctx.Value(contextKey{}).(spiffeid.ID)
	return id, ok
}
