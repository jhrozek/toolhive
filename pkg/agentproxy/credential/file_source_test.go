// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSPIFFEID = "spiffe://example.org/test/workload"

// generateSPIFFECert creates a self-signed X.509 certificate with a
// SPIFFE URI SAN and returns PEM-encoded cert and key bytes. The
// optional ca parameters allow signing the cert with a CA; pass nil to
// self-sign.
func generateSPIFFECert(
	t *testing.T, spiffeID string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey,
) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	u, err := url.Parse(spiffeID)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "SPIFFE test workload"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},

		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	parent := template
	signingKey := key
	if caCert != nil && caKey != nil {
		parent = caCert
		signingKey = caKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signingKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// generateCACert creates a self-signed CA certificate for use in tests.
func generateCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return cert, key, certPEM
}

// writeCertFiles writes cert and key PEM data to the given directory
// using the standard cert-manager file names.
func writeCertFiles(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600))
}

func TestFileSource_LoadsInitialSVID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	certPEM, keyPEM := generateSPIFFECert(t, testSPIFFEID, nil, nil)
	writeCertFiles(t, dir, certPEM, keyPEM)

	fs, err := NewFileSource(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })

	svid, err := fs.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, testSPIFFEID, svid.ID.String())
}

func TestFileSource_DetectsRotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	originalURI := "spiffe://example.org/test/original"

	certPEM, keyPEM := generateSPIFFECert(t, originalURI, nil, nil)
	writeCertFiles(t, dir, certPEM, keyPEM)

	fs, err := NewFileSource(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fs.Close() })

	// Verify initial SVID.
	svid, err := fs.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, originalURI, svid.ID.String())

	// Write new cert with a different SPIFFE ID.
	rotatedURI := "spiffe://example.org/test/rotated"
	newCert, newKey := generateSPIFFECert(t, rotatedURI, nil, nil)
	writeCertFiles(t, dir, newCert, newKey)

	// Wait for the debounce + some margin for the watcher to fire.
	require.Eventually(t, func() bool {
		s, err := fs.GetX509SVID()
		if err != nil {
			return false
		}
		return s.ID.String() == rotatedURI
	}, 3*time.Second, 50*time.Millisecond, "SVID was not rotated within timeout")
}

func TestFileSource_InvalidCertFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("not a cert"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), []byte("not a key"), 0o600))

	_, err := NewFileSource(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
	)
	require.Error(t, err)
}

func TestFileSource_Close(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	certPEM, keyPEM := generateSPIFFECert(t, testSPIFFEID, nil, nil)
	writeCertFiles(t, dir, certPEM, keyPEM)

	fs, err := NewFileSource(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
	)
	require.NoError(t, err)

	// Close should not panic and should return no error.
	require.NoError(t, fs.Close())

	// After close, GetX509SVID should still return the last loaded SVID
	// (the atomic pointer is not cleared).
	svid, err := fs.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, testSPIFFEID, svid.ID.String())
}
