// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/stacklok/toolhive/pkg/agentproxy/credential"
	"github.com/stacklok/toolhive/pkg/agentproxy/exchanger"
	"github.com/stacklok/toolhive/pkg/agentproxy/proxy"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the agent proxy",
	RunE:  runProxy,
}

func init() {
	flags := runCmd.Flags()

	flags.String("upstream-url", "", "Upstream MCP server URL (e.g., https://mcp-fetch-proxy.toolhive-system.svc:8080)")
	flags.String("listen-addr", ":8080", "Address to listen on")
	flags.String("spiffe-cert-dir", "/var/run/secrets/spiffe.io", "Path to SPIFFE CSI driver certs")
	flags.String("trust-domain", "", "SPIFFE trust domain (e.g., toolhive.dev)")
	flags.String("subject-token-type", "access_token", "Type of incoming user token")

	// Mark required flags
	for _, name := range []string{"upstream-url", "trust-domain"} {
		if err := runCmd.MarkFlagRequired(name); err != nil {
			slog.Error(fmt.Sprintf("Error marking flag required: %v", err))
		}
	}

	// Bind all flags to viper with AGENT_PROXY_ env prefix
	viper.SetEnvPrefix("AGENT_PROXY")
	for _, name := range []string{"upstream-url", "listen-addr", "spiffe-cert-dir", "trust-domain", "subject-token-type"} {
		if err := viper.BindPFlag(name, flags.Lookup(name)); err != nil {
			slog.Error(fmt.Sprintf("Error binding flag %s: %v", name, err))
		}
	}
}

func runProxy(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	upstreamURL := viper.GetString("upstream-url")
	listenAddr := viper.GetString("listen-addr")
	certDir := viper.GetString("spiffe-cert-dir")
	trustDomain := viper.GetString("trust-domain")
	subjectTokenType := viper.GetString("subject-token-type")

	slog.Info("starting agent proxy",
		"upstream_url", upstreamURL,
		"listen_addr", listenAddr,
		"cert_dir", certDir,
		"trust_domain", trustDomain,
	)

	// Create mTLS client from SPIFFE certificates
	mtlsClient, spiffeID, credSource, err := credential.NewMTLSClient(certDir, trustDomain)
	if err != nil {
		return fmt.Errorf("creating mTLS client: %w", err)
	}
	defer func() {
		if closeErr := credSource.Close(); closeErr != nil {
			slog.Warn("failed to close credential source", "error", closeErr)
		}
	}()

	slog.Info("loaded SPIFFE identity", "spiffe_id", spiffeID.String())

	// Derive token endpoint from upstream URL
	tokenEndpoint := upstreamURL + "/oauth/token"

	// Create token exchanger
	ex := exchanger.New(mtlsClient, spiffeID, tokenEndpoint, upstreamURL)
	ex.SubjectTokenType = subjectTokenType

	// Bootstrap: obtain agent's own SPIFFE JWT via client_credentials grant
	if err := ex.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	// Extract TLS config from the mTLS client's transport for the reverse proxy
	transport, ok := mtlsClient.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("unexpected transport type: %T", mtlsClient.Transport)
	}

	// Create and start the reverse proxy
	p, err := proxy.New(listenAddr, upstreamURL, ex, transport.TLSClientConfig)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	return p.Start(ctx)
}
