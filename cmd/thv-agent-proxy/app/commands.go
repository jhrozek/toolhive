// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package app provides the entry point for the thv-agent-proxy command-line application.
package app

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:               "thv-agent-proxy",
	DisableAutoGenTag: true,
	Short:             "SPIFFE delegation proxy for ToolHive MCP agent sidecars",
	Long: `thv-agent-proxy is a sidecar proxy that authenticates agents via SPIFFE mTLS,
bootstraps agent identity through client_credentials grant, and exchanges
incoming user tokens for delegated JWTs using RFC 8693 token exchange.`,
	Run: func(cmd *cobra.Command, _ []string) {
		// If no subcommand is provided, print help
		if err := cmd.Help(); err != nil {
			slog.Error(fmt.Sprintf("Error displaying help: %v", err))
		}
	},
}

// NewRootCmd creates a new root command for the thv-agent-proxy CLI.
func NewRootCmd() *cobra.Command {
	// Add persistent flags
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug mode")
	err := viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	if err != nil {
		slog.Error(fmt.Sprintf("Error binding debug flag: %v", err))
	}

	// Bind TOOLHIVE_DEBUG environment variable to viper debug config
	// This allows setting debug mode via environment variable
	err = viper.BindEnv("debug", "TOOLHIVE_DEBUG")
	if err != nil {
		slog.Error(fmt.Sprintf("Error binding TOOLHIVE_DEBUG env var: %v", err))
	}

	// Add subcommands
	rootCmd.AddCommand(runCmd)

	return rootCmd
}
