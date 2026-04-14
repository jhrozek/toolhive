// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMTLSClient_Success(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trustDomain := "example.org"

	caCert, caKey, caPEM := generateCACert(t)
	certPEM, keyPEM := generateSPIFFECert(t, testSPIFFEID, caCert, caKey)

	writeCertFiles(t, dir, certPEM, keyPEM)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600))

	client, spiffeID, source, err := NewMTLSClient(dir, trustDomain)
	require.NoError(t, err)
	t.Cleanup(func() { _ = source.Close() })

	assert.NotNil(t, client)
	assert.NotNil(t, client.Transport)
	assert.Equal(t, testSPIFFEID, spiffeID.String())
}

func TestNewMTLSClient_MissingFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	client, _, source, err := NewMTLSClient(dir, "example.org")
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Nil(t, source)
}

func TestNewMTLSClient_InvalidTrustDomain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// The trust domain parser rejects empty strings and strings with
	// path separators in invalid positions.
	client, _, source, err := NewMTLSClient(dir, "")
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Nil(t, source)
}
