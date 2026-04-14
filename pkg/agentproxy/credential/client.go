// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// NewMTLSClient creates an HTTP client configured for mTLS using SPIFFE
// X.509-SVIDs from the given certificate directory. It also returns the
// SPIFFE ID extracted from the certificate.
//
// The certDir should contain tls.crt, tls.key, and ca.crt files
// (standard cert-manager CSI driver layout).
//
// The client certificate (SVID) is automatically reloaded when files change
// on disk (via FileSource). The CA bundle is loaded once at startup and is
// NOT watched for rotation — CA bundles change infrequently and a process
// restart is acceptable when the trust anchor rotates.
//
// Server verification uses standard TLS (DNS SANs against the CA bundle),
// not SPIFFE peer validation. This is correct because the MCP server's TLS
// cert has DNS SANs (e.g., mcp-fetch-proxy.toolhive-system.svc), not a
// SPIFFE URI SAN. The SPIFFE identity is only on the client side.
func NewMTLSClient(
	certDir string, trustDomain string,
) (client *http.Client, spiffeID spiffeid.ID, source *FileSource, err error) {
	if trustDomain == "" {
		return nil, spiffeid.ID{}, nil, fmt.Errorf("trust domain must not be empty")
	}

	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")
	caPath := filepath.Join(certDir, "ca.crt")

	source, err = NewFileSource(certPath, keyPath)
	if err != nil {
		return nil, spiffeid.ID{}, nil, fmt.Errorf("creating file source: %w", err)
	}

	// Load the CA bundle into a standard x509.CertPool for server verification.
	caCertPool, err := loadCACertPool(caPath)
	if err != nil {
		_ = source.Close()
		return nil, spiffeid.ID{}, nil, fmt.Errorf("loading CA bundle: %w", err)
	}

	// Use MTLSWebClientConfig: presents the SPIFFE SVID as the client cert
	// but verifies the server using standard web PKI (DNS SANs + CA pool).
	tlsCfg := tlsconfig.MTLSWebClientConfig(source, caCertPool)

	svid, err := source.GetX509SVID()
	if err != nil {
		_ = source.Close()
		return nil, spiffeid.ID{}, nil, fmt.Errorf("getting initial SVID: %w", err)
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	return client, svid.ID, source, nil
}

// loadCACertPool reads a PEM-encoded CA certificate file and returns
// an x509.CertPool containing it.
func loadCACertPool(path string) (*x509.CertPool, error) {
	caCert, err := loadPEMFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", path)
	}
	return pool, nil
}

// loadPEMFile reads a PEM-encoded file.
func loadPEMFile(path string) ([]byte, error) {
	//nolint:gosec // G304: path is from trusted configuration, not user input
	return os.ReadFile(path)
}
