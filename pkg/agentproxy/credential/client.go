// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
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
func NewMTLSClient(
	certDir string, trustDomain string,
) (client *http.Client, spiffeID spiffeid.ID, source *FileSource, err error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, spiffeid.ID{}, nil, fmt.Errorf("parsing trust domain: %w", err)
	}

	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")
	caPath := filepath.Join(certDir, "ca.crt")

	source, err = NewFileSource(certPath, keyPath)
	if err != nil {
		return nil, spiffeid.ID{}, nil, fmt.Errorf("creating file source: %w", err)
	}

	bundle, err := x509bundle.Load(td, caPath)
	if err != nil {
		_ = source.Close()
		return nil, spiffeid.ID{}, nil, fmt.Errorf("loading CA bundle: %w", err)
	}

	tlsCfg := tlsconfig.MTLSClientConfig(source, bundle, tlsconfig.AuthorizeMemberOf(td))

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
